// Supabase Edge Function: platform-auth-login
// Purpose: move All Communities Dashboard password verification off the browser
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY
//   PLATFORM_PASSWORD_SALT

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS') || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com').split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return { 'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Vary': 'Origin' }
}

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function getClientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown'
}

async function logEvent(supabase: any, payload: Record<string, unknown>) {
  await supabase.from('platform_security_events').insert(payload)
}

const MAX_FAILED_LOGIN_ATTEMPTS = 5
const LOCK_DURATION_MS = 48 * 60 * 60 * 1000

function generateChallengeToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const random = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  return `pc_${crypto.randomUUID().replace(/-/g, '')}_${random}`
}

function isLocked(account: Record<string, unknown>): boolean {
  const lockedUntil = String(account.lockedUntil || '')
  return !!lockedUntil && new Date(lockedUntil).getTime() > Date.now()
}

function lockMessage(account: Record<string, unknown>): string {
  return `Account locked until ${new Date(String(account.lockedUntil || '')).toISOString()} after too many failed login attempts.`
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method !== 'POST' && req.method !== 'OPTIONS') return new Response('Method not allowed.', { status: 405, headers: corsHeaders })
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const passwordSalt = Deno.env.get('PLATFORM_PASSWORD_SALT') || ''
  const supabase = createClient(supabaseUrl, serviceRoleKey)

  try {
    const { email, password } = await req.json()
    const normalizedEmail = String(email || '').trim().toLowerCase()
    const plainPassword = String(password || '')
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    const { data: rateRows, error: rateError } = await supabase.rpc('consume_auth_rate_limit', {
      p_key: `platform-login:${normalizedEmail}:${requestIp}`,
      p_limit: 10,
      p_window_seconds: 900,
    })
    if (rateError) throw new Error(rateError.message)
    if (Array.isArray(rateRows) && rateRows[0]?.allowed === false) {
      return new Response(JSON.stringify({ error: 'Too many login attempts. Please try again later.' }), {
        status: 429,
        headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Retry-After': '900' },
      })
    }

    if (!normalizedEmail || !plainPassword) {
      await logEvent(supabase, {
        event_type: 'platform_login',
        actor_email: normalizedEmail || null,
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { reason: 'missing_credentials' },
      })
      return new Response(JSON.stringify({ error: 'Email and password are required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const passwordHash = await sha256(plainPassword + passwordSalt)
    const { data, error } = await supabase.from('platform_kv').select('key, value').in('key', ['admin', 'platformStaffList'])

    if (error) {
      throw new Error(error.message)
    }

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const admin = (rows.admin || {}) as Record<string, unknown>
    const platformStaffList = Array.isArray(rows.platformStaffList) ? rows.platformStaffList as Record<string, unknown>[] : []

    const adminEmailMatches = String(admin.email || '').toLowerCase() === normalizedEmail
    const staffByEmail = platformStaffList.find(entry => String(entry.email || '').toLowerCase() === normalizedEmail && entry.active !== false)
    const accountForLock = adminEmailMatches ? admin : (staffByEmail || null)

    if (accountForLock && isLocked(accountForLock)) {
      await logEvent(supabase, {
        event_type: 'platform_login',
        actor_email: normalizedEmail,
        actor_type: adminEmailMatches ? 'admin' : 'staff',
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { reason: 'account_locked', lockedUntil: accountForLock.lockedUntil },
      })
      return new Response(JSON.stringify({ error: lockMessage(accountForLock) }), {
        status: 423,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    let accountType = ''
    let account: Record<string, unknown> | null = null

    if (adminEmailMatches && admin.password === passwordHash) {
      accountType = 'admin'
      account = {
        email: normalizedEmail,
        name: admin.name || 'Platform Admin',
        platformRole: 'superadmin',
        scope: 'all',
        mustChangePassword: !!admin.mustChangePassword,
        requiresTotp: !!admin.totpSecret && admin.totpVerified !== false,
        totpSetupRequired: !admin.totpSecret || admin.totpVerified === false,
      }
    } else {
      const staff = staffByEmail && staffByEmail.password === passwordHash ? staffByEmail : null
      if (staff) {
        const platformRole = String(staff.role || 'developer')
        accountType = 'staff'
        account = {
          id: staff.id,
          email: normalizedEmail,
          name: staff.name || 'Platform Staff',
          platformRole,
          scope: platformRole === 'superadmin' ? 'all' : (staff.scope || 'all'),
          mustChangePassword: !!staff.mustChangePassword,
          requiresTotp: !!staff.totpSecret && staff.totpVerified !== false,
          totpSetupRequired: !staff.totpSecret || staff.totpVerified === false,
        }
      }
    }

    await logEvent(supabase, {
      event_type: 'platform_login',
      actor_email: normalizedEmail,
      actor_type: accountType || null,
      actor_scope: account ? account.scope : null,
      success: !!account,
      request_ip: requestIp,
      user_agent: userAgent,
      details: account ? { platformRole: account.platformRole } : { reason: 'invalid_credentials' },
    })

    if (!account) {
      if (accountForLock) {
        const previousLockExpired = !!accountForLock.lockedUntil && new Date(String(accountForLock.lockedUntil)).getTime() <= Date.now()
        const failedLoginAttempts = (previousLockExpired ? 0 : Number(accountForLock.failedLoginAttempts || 0)) + 1
        const lockedUntil = failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS
          ? new Date(Date.now() + LOCK_DURATION_MS).toISOString()
          : null

        if (adminEmailMatches) {
          await supabase.from('platform_kv').upsert({
            key: 'admin',
            value: {
              ...admin,
              failedLoginAttempts,
              lastFailedLoginAt: new Date().toISOString(),
              ...(lockedUntil ? { lockedUntil } : { lockedUntil: null }),
            },
          })
        } else {
          await supabase.from('platform_kv').upsert({
            key: 'platformStaffList',
            value: platformStaffList.map((entry) => (
              String(entry.email || '').toLowerCase() === normalizedEmail
                ? {
                    ...entry,
                    failedLoginAttempts,
                    lastFailedLoginAt: new Date().toISOString(),
                    ...(lockedUntil ? { lockedUntil } : { lockedUntil: null }),
                  }
                : entry
            )),
          })
        }

        if (lockedUntil) {
          return new Response(JSON.stringify({ error: 'Too many failed login attempts. Account locked for 48 hours.' }), {
            status: 423,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          })
        }
      }
      return new Response(JSON.stringify({ error: 'Invalid email or password.' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (accountForLock && (Number(accountForLock.failedLoginAttempts || 0) > 0 || !!accountForLock.lockedUntil)) {
      if (accountType === 'admin') {
        await supabase.from('platform_kv').upsert({
          key: 'admin',
          value: { ...admin, failedLoginAttempts: 0, lockedUntil: null, lastFailedLoginAt: null },
        })
      } else {
        await supabase.from('platform_kv').upsert({
          key: 'platformStaffList',
          value: platformStaffList.map((entry) => (
            String(entry.email || '').toLowerCase() === normalizedEmail
              ? { ...entry, failedLoginAttempts: 0, lockedUntil: null, lastFailedLoginAt: null }
              : entry
          )),
        })
      }
    }

    const challengeToken = generateChallengeToken()
    const challengeExpiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString()
    await supabase.from('platform_mfa_challenges').delete().eq('email', normalizedEmail)
    await supabase.from('platform_mfa_challenges').insert({
      token: challengeToken,
      email: normalizedEmail,
      account_type: accountType,
      expires_at: challengeExpiresAt,
      metadata: { account },
    })

    return new Response(JSON.stringify({
      ok: true,
      accountType,
      account: {
        ...account,
        challengeToken,
        challengeExpiresAt,
      },
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[platform-auth-login]', err)
    return new Response(JSON.stringify({ error: 'Unable to complete platform login.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

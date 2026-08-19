// Supabase Edge Function: community-auth-login
// Purpose: move community admin/staff/owner-tenant password verification off the browser
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY
//   PLATFORM_PASSWORD_SALT

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { hashSessionToken } from '../_shared/session.ts'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS')
  || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com')
  .split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session, x-community-session',
    'Vary': 'Origin',
  }
}

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function getClientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown'
}

async function logEvent(supabase: any, payload: Record<string, unknown>) {
  await supabase.from('community_security_events').insert(payload)
}

const MAX_FAILED_LOGIN_ATTEMPTS = 5
const LOCK_DURATION_MS = 48 * 60 * 60 * 1000

function generateSessionToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const random = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  return `cs_${crypto.randomUUID().replace(/-/g, '')}_${random}`
}

function generateChallengeToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const random = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  return `cc_${crypto.randomUUID().replace(/-/g, '')}_${random}`
}

function isLocked(account: Record<string, unknown>): boolean {
  const lockedUntil = String(account.lockedUntil || '')
  return !!lockedUntil && new Date(lockedUntil).getTime() > Date.now()
}

function lockedUntilMessage(account: Record<string, unknown>): string {
  const lockedUntil = new Date(String(account.lockedUntil || ''))
  return `Account locked until ${lockedUntil.toISOString()} after too many failed login attempts.`
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method !== 'POST' && req.method !== 'OPTIONS') return new Response('Method not allowed.', { status: 405, headers: corsHeaders })
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const passwordSalt = Deno.env.get('PLATFORM_PASSWORD_SALT') || ''
  const supabase = createClient(supabaseUrl, serviceRoleKey)

  try {
    const { communityId, email, password } = await req.json()
    const cid = String(communityId || '').trim()
    const normalizedEmail = String(email || '').trim().toLowerCase()
    const plainPassword = String(password || '')
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    const { data: rateRows, error: rateError } = await supabase.rpc('consume_auth_rate_limit', {
      p_key: `community-login:${cid}:${normalizedEmail}:${requestIp}`,
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

    if (!cid || !normalizedEmail || !plainPassword) {
      return new Response(JSON.stringify({ error: 'Community, email, and password are required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const passwordHash = await sha256(plainPassword + passwordSalt)
    const { data, error } = await supabase
      .from('community_kv')
      .select('key, value')
      .eq('community_id', cid)
      .in('key', ['admin', 'staffList', 'owners'])

    if (error) throw new Error(error.message)

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const admin = (rows.admin || {}) as Record<string, unknown>
    const staffList = Array.isArray(rows.staffList) ? rows.staffList as Record<string, unknown>[] : []
    const owners = Array.isArray(rows.owners) ? rows.owners as Record<string, unknown>[] : []

    const adminEmailMatches = String(admin.email || '').toLowerCase() === normalizedEmail
    const staffByEmail = staffList.find((entry) => String(entry.email || '').toLowerCase() === normalizedEmail && entry.active !== false)
    const ownerMatchesByEmail = owners.filter((entry) => String(entry.email || '').toLowerCase() === normalizedEmail)
    const accountForLock = adminEmailMatches ? admin : (staffByEmail || ownerMatchesByEmail[0] || null)

    if (accountForLock && isLocked(accountForLock)) {
      await logEvent(supabase, {
        event_type: 'community_login',
        community_id: cid,
        actor_email: normalizedEmail,
        actor_role: adminEmailMatches ? 'admin' : (staffByEmail ? 'staff' : 'owner'),
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { reason: 'account_locked', lockedUntil: accountForLock.lockedUntil },
      })
      return new Response(JSON.stringify({ error: lockedUntilMessage(accountForLock) }), {
        status: 423,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    let sessionRole = ''
    let sessionMeta: Record<string, unknown> = {}
    let accountType = ''
    let requiresTotp = false
    let totpSetupRequired = false

    if (adminEmailMatches && admin.password === passwordHash) {
      accountType = 'admin'
      sessionRole = 'admin'
      const totpEnabled = admin.totpEnabled !== false
      requiresTotp = totpEnabled && !!admin.totpSecret && admin.totpVerified !== false
      totpSetupRequired = totpEnabled && (!admin.totpSecret || admin.totpVerified === false)
      sessionMeta = { staffName: 'Admin', staffRole: 'superadmin', mustChangePassword: !!admin.mustChangePassword }
    } else {
      const staff = staffByEmail && staffByEmail.password === passwordHash ? staffByEmail : null
      if (staff) {
        accountType = 'staff'
        sessionRole = 'admin'
        const totpEnabled = staff.totpEnabled !== false
        requiresTotp = totpEnabled && !!staff.totpSecret && staff.totpVerified !== false
        totpSetupRequired = totpEnabled && (!staff.totpSecret || staff.totpVerified === false)
        sessionMeta = {
          staffId: staff.id || null,
          staffName: staff.name || 'Staff',
          staffRole: staff.role || 'staff',
          mustChangePassword: !!staff.mustChangePassword,
        }
      } else {
        const ownerMatches = ownerMatchesByEmail.filter((entry) => entry.password === passwordHash)
        if (ownerMatches.length) {
          sessionRole = 'user'
          sessionMeta = {
            ownerIds: ownerMatches.map((entry) => entry.id).filter(Boolean),
            mustChangePassword: ownerMatches.some((entry) => !!entry.mustChangePassword),
          }
        }
      }
    }

    await logEvent(supabase, {
      event_type: 'community_login',
      community_id: cid,
      actor_email: normalizedEmail,
      actor_role: sessionRole || null,
      success: !!sessionRole,
      request_ip: requestIp,
      user_agent: userAgent,
      details: sessionRole ? {} : { reason: 'invalid_credentials' },
    })

    if (!sessionRole) {
      if (accountForLock) {
        const previousLockExpired = !!accountForLock.lockedUntil && new Date(String(accountForLock.lockedUntil)).getTime() <= Date.now()
        const failedLoginAttempts = (previousLockExpired ? 0 : Number(accountForLock.failedLoginAttempts || 0)) + 1
        const lockedUntil = failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS
          ? new Date(Date.now() + LOCK_DURATION_MS).toISOString()
          : null
        if (adminEmailMatches) {
          await supabase.from('community_kv').upsert({
            community_id: cid,
            key: 'admin',
            value: {
              ...admin,
              failedLoginAttempts,
              lastFailedLoginAt: new Date().toISOString(),
              ...(lockedUntil ? { lockedUntil } : { lockedUntil: null }),
            },
          })
        } else if (staffByEmail) {
          await supabase.from('community_kv').upsert({
            community_id: cid,
            key: 'staffList',
            value: staffList.map((entry) => (
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
        } else {
          await supabase.from('community_kv').upsert({
            community_id: cid,
            key: 'owners',
            value: owners.map((entry) => (
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
          return new Response(JSON.stringify({ error: `Too many failed login attempts. Account locked for 48 hours.` }), {
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
        await supabase.from('community_kv').upsert({
          community_id: cid,
          key: 'admin',
          value: { ...admin, failedLoginAttempts: 0, lockedUntil: null, lastFailedLoginAt: null },
        })
      } else if (accountType === 'staff') {
        await supabase.from('community_kv').upsert({
          community_id: cid,
          key: 'staffList',
          value: staffList.map((entry) => (
            String(entry.email || '').toLowerCase() === normalizedEmail
              ? { ...entry, failedLoginAttempts: 0, lockedUntil: null, lastFailedLoginAt: null }
              : entry
          )),
        })
      } else if (sessionRole === 'user') {
        await supabase.from('community_kv').upsert({
          community_id: cid,
          key: 'owners',
          value: owners.map((entry) => (
            String(entry.email || '').toLowerCase() === normalizedEmail
              ? { ...entry, failedLoginAttempts: 0, lockedUntil: null, lastFailedLoginAt: null }
              : entry
          )),
        })
      }
    }

    if (sessionRole === 'user' || (sessionRole === 'admin' && !requiresTotp && !totpSetupRequired)) {
      const sessionToken = generateSessionToken()
      const storedSessionToken = await hashSessionToken(sessionToken)
      const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString()
      await supabase.from('community_sessions').delete().eq('community_id', cid).eq('email', normalizedEmail)
      await supabase.from('community_sessions').insert({
        token: storedSessionToken,
        community_id: cid,
        email: normalizedEmail,
        role: sessionRole,
        expires_at: expiresAt,
        metadata: sessionMeta,
      })

      return new Response(JSON.stringify({
        ok: true,
        session: {
          communityId: cid,
          email: normalizedEmail,
          role: sessionRole,
          sessionToken,
          expiresAt,
          ...sessionMeta,
        },
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const challengeToken = generateChallengeToken()
    const challengeExpiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString()
    await supabase.from('community_mfa_challenges').delete().eq('community_id', cid).eq('email', normalizedEmail)
    await supabase.from('community_mfa_challenges').insert({
      token: challengeToken,
      community_id: cid,
      email: normalizedEmail,
      account_type: accountType,
      expires_at: challengeExpiresAt,
      metadata: {
        sessionRole,
        sessionMeta,
        requiresTotp,
        totpSetupRequired,
      },
    })

    return new Response(JSON.stringify({
      ok: true,
      requiresTotp,
      totpSetupRequired,
      account: {
        communityId: cid,
        email: normalizedEmail,
        role: sessionRole,
        challengeToken,
        challengeExpiresAt,
        mustChangePassword: !!sessionMeta.mustChangePassword,
        requiresTotp,
        totpSetupRequired,
        ...sessionMeta,
      },
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[community-auth-login]', err)
    return new Response(JSON.stringify({ error: 'Unable to complete community login.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

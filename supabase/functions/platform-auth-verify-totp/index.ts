// Supabase Edge Function: platform-auth-verify-totp
// Purpose: verify or set up TOTP for All Communities Dashboard users server-side
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { hashSessionToken } from '../_shared/session.ts'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS') || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com').split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return { 'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session', 'Vary': 'Origin' }
}

function generateSessionToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const random = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  return `ps_${crypto.randomUUID().replace(/-/g, '')}_${random}`
}

function b32Decode(str: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  const out: number[] = []
  str.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '').split('').forEach((ch) => {
    value = (value << 5) | alphabet.indexOf(ch)
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  })
  return new Uint8Array(out)
}

async function generateTotpCode(secret: string, counter = Math.floor(Date.now() / 30000)): Promise<string> {
  const key = await crypto.subtle.importKey('raw', b32Decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const buffer = new ArrayBuffer(8)
  const view = new DataView(buffer)
  view.setUint32(0, Math.floor(counter / 0x100000000), false)
  view.setUint32(4, counter >>> 0, false)
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, buffer))
  const offset = signature[signature.length - 1] & 0x0f
  const binary = ((signature[offset] & 0x7f) << 24)
    | ((signature[offset + 1] & 0xff) << 16)
    | ((signature[offset + 2] & 0xff) << 8)
    | (signature[offset + 3] & 0xff)
  return String(binary % 1000000).padStart(6, '0')
}

async function verifyTotpCode(secret: string, code: string): Promise<boolean> {
  const clean = String(code || '').replace(/\D/g, '')
  if (clean.length !== 6) return false
  const current = Math.floor(Date.now() / 30000)
  for (let offset = -1; offset <= 1; offset++) {
    if (await generateTotpCode(secret, current + offset) === clean) return true
  }
  return false
}

function getClientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown'
}

async function logEvent(supabase: any, payload: Record<string, unknown>) {
  await supabase.from('platform_security_events').insert(payload)
}

async function recordFailedChallengeAttempt(supabase: any, challengeRow: any, reason: string) {
  const metadata = (challengeRow?.metadata || {}) as Record<string, unknown>
  const attempts = Number(metadata.attempts || 0) + 1
  const nextMetadata = {
    ...metadata,
    attempts,
    lastFailureReason: reason,
    lastFailureAt: new Date().toISOString(),
  }
  if (attempts >= 5) {
    await supabase.from('platform_mfa_challenges').delete().eq('token', challengeRow.token)
  } else {
    await supabase.from('platform_mfa_challenges').update({ metadata: nextMetadata }).eq('token', challengeRow.token)
  }
  return attempts
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
  const supabase = createClient(supabaseUrl, serviceRoleKey)

  try {
    const { email, accountType, setupSecret, code, challengeToken } = await req.json()
    const normalizedEmail = String(email || '').trim().toLowerCase()
    const challenge = String(challengeToken || '')
    const cleanCode = String(code || '').replace(/\D/g, '')
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    if (!normalizedEmail || !accountType || !challenge || cleanCode.length !== 6) {
      return new Response(JSON.stringify({ error: 'Email, account type, login challenge, and code are required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { data: challengeRow, error: challengeErr } = await supabase
      .from('platform_mfa_challenges')
      .select('*')
      .eq('token', challenge)
      .eq('email', normalizedEmail)
      .eq('account_type', String(accountType))
      .maybeSingle()

    if (challengeErr) throw new Error(challengeErr.message)
    if (!challengeRow || challengeRow.expires_at <= new Date().toISOString()) {
      await logEvent(supabase, {
        event_type: 'platform_totp_verify',
        actor_email: normalizedEmail,
        actor_type: accountType,
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { reason: 'missing_or_expired_challenge' },
      })
      return new Response(JSON.stringify({ error: 'Login challenge expired. Please sign in again.' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }
    const challengeAttempts = Number((challengeRow.metadata || {}).attempts || 0)
    if (challengeAttempts >= 5) {
      await supabase.from('platform_mfa_challenges').delete().eq('token', challenge)
      await logEvent(supabase, {
        event_type: 'platform_totp_verify',
        actor_email: normalizedEmail,
        actor_type: accountType,
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { reason: 'too_many_invalid_codes' },
      })
      return new Response(JSON.stringify({ error: 'Too many invalid authenticator codes. Please sign in again.' }), {
        status: 429,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { data, error } = await supabase.from('platform_kv').select('key, value').in('key', ['admin', 'platformStaffList'])
    if (error) throw new Error(error.message)

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const admin = (rows.admin || {}) as Record<string, unknown>
    const platformStaffList = Array.isArray(rows.platformStaffList) ? rows.platformStaffList as Record<string, unknown>[] : []

    let platformRole = 'superadmin'
    let scope = 'all'
    let persisted = false
    let secretToUse = ''
    let sessionRole = 'platform_admin'
    let mustChangePassword = false

    if (accountType === 'admin') {
      if (String(admin.email || '').toLowerCase() !== normalizedEmail) {
        return new Response(JSON.stringify({ error: 'Account not found.' }), {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      secretToUse = String(admin.totpSecret || setupSecret || '')
      if (!secretToUse || !(await verifyTotpCode(secretToUse, cleanCode))) {
        const attempts = await recordFailedChallengeAttempt(supabase, challengeRow, 'invalid_code')
        await logEvent(supabase, {
          event_type: 'platform_totp_verify',
          actor_email: normalizedEmail,
          actor_type: 'admin',
          actor_scope: 'all',
          success: false,
          request_ip: requestIp,
          user_agent: userAgent,
          details: { reason: attempts >= 5 ? 'too_many_invalid_codes' : 'invalid_code', attempts },
        })
        return new Response(JSON.stringify({ error: attempts >= 5 ? 'Too many invalid authenticator codes. Please sign in again.' : 'Invalid authenticator code.' }), {
          status: attempts >= 5 ? 429 : 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      mustChangePassword = !!admin.mustChangePassword
      if (!admin.totpSecret || admin.totpVerified === false) {
        const updatedAdmin = { ...admin, totpSecret: secretToUse, totpVerified: true }
        await supabase.from('platform_kv').upsert({ key: 'admin', value: updatedAdmin })
        persisted = true
      }
    } else {
      const staff = platformStaffList.find(entry => String(entry.email || '').toLowerCase() === normalizedEmail && entry.active !== false)
      if (!staff) {
        return new Response(JSON.stringify({ error: 'Account not found.' }), {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      platformRole = String(staff.role || 'developer')
      scope = platformRole === 'superadmin' ? 'all' : String(staff.scope || 'all')
      sessionRole = platformRole === 'superadmin' ? 'platform_admin' : 'platform_staff'
      mustChangePassword = !!staff.mustChangePassword
      secretToUse = String(staff.totpSecret || setupSecret || '')
      if (!secretToUse || !(await verifyTotpCode(secretToUse, cleanCode))) {
        const attempts = await recordFailedChallengeAttempt(supabase, challengeRow, 'invalid_code')
        await logEvent(supabase, {
          event_type: 'platform_totp_verify',
          actor_email: normalizedEmail,
          actor_type: 'staff',
          actor_scope: scope,
          success: false,
          request_ip: requestIp,
          user_agent: userAgent,
          details: { reason: attempts >= 5 ? 'too_many_invalid_codes' : 'invalid_code', attempts },
        })
        return new Response(JSON.stringify({ error: attempts >= 5 ? 'Too many invalid authenticator codes. Please sign in again.' : 'Invalid authenticator code.' }), {
          status: attempts >= 5 ? 429 : 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      if (!staff.totpSecret || staff.totpVerified === false) {
        const updatedStaffList = platformStaffList.map(entry => {
          if (String(entry.email || '').toLowerCase() !== normalizedEmail) return entry
          return { ...entry, totpSecret: secretToUse, totpVerified: true }
        })
        await supabase.from('platform_kv').upsert({ key: 'platformStaffList', value: updatedStaffList })
        persisted = true
      }
    }

    await logEvent(supabase, {
      event_type: 'platform_totp_verify',
      actor_email: normalizedEmail,
      actor_type: accountType,
      actor_scope: scope,
      success: true,
      request_ip: requestIp,
      user_agent: userAgent,
      details: { setupCompleted: persisted },
    })

    const sessionToken = generateSessionToken()
    const storedSessionToken = await hashSessionToken(sessionToken)
    const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString()

    await supabase.from('platform_sessions').delete().eq('email', normalizedEmail)
    await supabase.from('platform_sessions').insert({
      token: storedSessionToken,
      email: normalizedEmail,
      role: accountType === 'admin' ? 'platform_admin' : sessionRole,
      scope,
      expires_at: expiresAt,
      metadata: {
        platformRole,
        accountType,
        mustChangePassword,
      },
    })
    await supabase.from('platform_mfa_challenges').delete().eq('token', challenge)

    return new Response(JSON.stringify({
      ok: true,
      session: {
        email: normalizedEmail,
        role: accountType === 'admin' ? 'platform_admin' : sessionRole,
        platformRole,
        scope,
        sessionToken,
        expiresAt,
        mustChangePassword,
      },
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[platform-auth-verify-totp]', err)
    return new Response(JSON.stringify({ error: 'Unable to verify authenticator code.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

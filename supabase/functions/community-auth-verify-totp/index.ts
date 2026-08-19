// Supabase Edge Function: community-auth-verify-totp
// Purpose: verify or set up TOTP for community super admin and admin-panel staff
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { hashSessionToken } from '../_shared/session.ts'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS') || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com').split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return { 'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session, x-community-session', 'Vary': 'Origin' }
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

function generateSessionToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const random = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
  return `cs_${crypto.randomUUID().replace(/-/g, '')}_${random}`
}

function getClientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown'
}

async function logEvent(supabase: any, payload: Record<string, unknown>) {
  await supabase.from('community_security_events').insert(payload)
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
    await supabase.from('community_mfa_challenges').delete().eq('token', challengeRow.token)
  } else {
    await supabase.from('community_mfa_challenges').update({ metadata: nextMetadata }).eq('token', challengeRow.token)
  }
  return attempts
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method !== 'POST' && req.method !== 'OPTIONS') return new Response('Method not allowed.', { status: 405, headers: corsHeaders })
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const supabase = createClient(supabaseUrl, serviceRoleKey)

  try {
    const { communityId, email, accountType, setupSecret, code, challengeToken } = await req.json()
    const cid = String(communityId || '').trim()
    const normalizedEmail = String(email || '').trim().toLowerCase()
    const challenge = String(challengeToken || '')
    const cleanCode = String(code || '').replace(/\D/g, '')
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    if (!cid || !normalizedEmail || !accountType || !challenge || cleanCode.length !== 6) {
      return new Response(JSON.stringify({ error: 'Community, email, account type, login challenge, and code are required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { data: challengeRow, error: challengeErr } = await supabase
      .from('community_mfa_challenges')
      .select('*')
      .eq('token', challenge)
      .eq('community_id', cid)
      .eq('email', normalizedEmail)
      .eq('account_type', String(accountType))
      .maybeSingle()

    if (challengeErr) throw new Error(challengeErr.message)
    if (!challengeRow || challengeRow.expires_at <= new Date().toISOString()) {
      await logEvent(supabase, {
        event_type: 'community_totp_verify',
        community_id: cid,
        actor_email: normalizedEmail,
        actor_role: accountType,
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
      await supabase.from('community_mfa_challenges').delete().eq('token', challenge)
      await logEvent(supabase, {
        event_type: 'community_totp_verify',
        community_id: cid,
        actor_email: normalizedEmail,
        actor_role: accountType,
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

    const { data, error } = await supabase
      .from('community_kv')
      .select('key, value')
      .eq('community_id', cid)
      .in('key', ['admin', 'staffList'])

    if (error) throw new Error(error.message)

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const admin = (rows.admin || {}) as Record<string, unknown>
    const staffList = Array.isArray(rows.staffList) ? rows.staffList as Record<string, unknown>[] : []

    let sessionMeta: Record<string, unknown> = {}
    let secretToUse = ''
    let mustChangePassword = false

    if (accountType === 'admin') {
      if (String(admin.email || '').toLowerCase() !== normalizedEmail) {
        return new Response(JSON.stringify({ error: 'Account not found.' }), {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      sessionMeta = { staffName: 'Admin', staffRole: 'superadmin' }
      mustChangePassword = !!admin.mustChangePassword
      secretToUse = String(admin.totpSecret || setupSecret || '')
      if (!secretToUse || !(await verifyTotpCode(secretToUse, cleanCode))) {
        const attempts = await recordFailedChallengeAttempt(supabase, challengeRow, 'invalid_code')
        await logEvent(supabase, {
          event_type: 'community_totp_verify',
          community_id: cid,
          actor_email: normalizedEmail,
          actor_role: accountType,
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
      if (!admin.totpSecret || admin.totpVerified === false) {
        await supabase.from('community_kv').upsert({
          community_id: cid,
          key: 'admin',
          value: { ...admin, totpSecret: secretToUse, totpVerified: true },
        })
      }
    } else {
      const staff = staffList.find((entry) => String(entry.email || '').toLowerCase() === normalizedEmail && entry.active !== false)
      if (!staff) {
        return new Response(JSON.stringify({ error: 'Account not found.' }), {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      sessionMeta = {
        staffId: staff.id || null,
        staffName: staff.name || 'Staff',
        staffRole: staff.role || 'staff',
      }
      mustChangePassword = !!staff.mustChangePassword
      secretToUse = String(staff.totpSecret || setupSecret || '')
      if (!secretToUse || !(await verifyTotpCode(secretToUse, cleanCode))) {
        const attempts = await recordFailedChallengeAttempt(supabase, challengeRow, 'invalid_code')
        await logEvent(supabase, {
          event_type: 'community_totp_verify',
          community_id: cid,
          actor_email: normalizedEmail,
          actor_role: accountType,
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
        const updated = staffList.map((entry) => (
          String(entry.email || '').toLowerCase() === normalizedEmail
            ? { ...entry, totpSecret: secretToUse, totpVerified: true }
            : entry
        ))
        await supabase.from('community_kv').upsert({ community_id: cid, key: 'staffList', value: updated })
      }
    }

    const sessionToken = generateSessionToken()
    const storedSessionToken = await hashSessionToken(sessionToken)
    const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString()
    await supabase.from('community_sessions').delete().eq('community_id', cid).eq('email', normalizedEmail)
    await supabase.from('community_sessions').insert({
      token: storedSessionToken,
      community_id: cid,
      email: normalizedEmail,
      role: 'admin',
      expires_at: expiresAt,
      metadata: { ...sessionMeta, mustChangePassword },
    })
    await supabase.from('community_mfa_challenges').delete().eq('token', challenge)

    await logEvent(supabase, {
      event_type: 'community_totp_verify',
      community_id: cid,
      actor_email: normalizedEmail,
      actor_role: accountType,
      success: true,
      request_ip: requestIp,
      user_agent: userAgent,
      details: {},
    })

    return new Response(JSON.stringify({
      ok: true,
      session: {
        communityId: cid,
        email: normalizedEmail,
        role: 'admin',
        sessionToken,
        expiresAt,
        mustChangePassword,
        ...sessionMeta,
      },
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[community-auth-verify-totp]', err)
    return new Response(JSON.stringify({ error: 'Unable to verify authenticator code.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

// Supabase Edge Function: community-auth-request-reset
// Purpose: create server-side OTP reset requests for community users
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY
//   OTP_HASH_PEPPER

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS') || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com').split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return { 'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session, x-community-session', 'Vary': 'Origin' }
}

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function genOtp(): string {
  const bytes = crypto.getRandomValues(new Uint32Array(1))
  return String(100000 + (bytes[0] % 900000))
}

function getClientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown'
}

async function logEvent(supabase: any, payload: Record<string, unknown>) {
  await supabase.from('community_security_events').insert(payload)
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method !== 'POST' && req.method !== 'OPTIONS') return new Response('Method not allowed.', { status: 405, headers: corsHeaders })
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const otpPepper = Deno.env.get('OTP_HASH_PEPPER') || ''
  const supabase = createClient(supabaseUrl, serviceRoleKey)

  try {
    const { email, communityId } = await req.json()
    const normalizedEmail = String(email || '').trim().toLowerCase()
    const cid = String(communityId || '').trim()
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    const { data: rateRows, error: rateError } = await supabase.rpc('consume_auth_rate_limit', {
      p_key: `community-reset:${cid}:${requestIp}`,
      p_limit: 3,
      p_window_seconds: 3600,
    })
    if (rateError) throw new Error(rateError.message)
    if (Array.isArray(rateRows) && rateRows[0]?.allowed === false) {
      return new Response(JSON.stringify({ ok: true, message: 'If the account exists, a reset OTP has been created.' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Retry-After': '3600' },
      })
    }

    if (!normalizedEmail || !cid) {
      return new Response(JSON.stringify({ error: 'Community and email are required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

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

    let accountType = ''
    if (String(admin.email || '').toLowerCase() === normalizedEmail) {
      accountType = 'admin'
    } else if (staffList.some((entry) => String(entry.email || '').toLowerCase() === normalizedEmail && entry.active !== false)) {
      accountType = 'staff'
    } else if (owners.some((entry) => String(entry.email || '').toLowerCase() === normalizedEmail)) {
      accountType = 'owner'
    }

    const publicResetEnabled = Deno.env.get('ENABLE_PUBLIC_PASSWORD_RESET') === 'true'
    const otp = genOtp()
    const otpHash = await sha256(otp + otpPepper)
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString()

    let resetRequestId: string | null = null
    if (accountType && publicResetEnabled) {
      const { data: insertedReset, error: insertErr } = await supabase.from('community_password_resets').insert({
        community_id: cid,
        email: normalizedEmail,
        account_type: accountType,
        otp_hash: otpHash,
        expires_at: expiresAt,
        request_ip: requestIp,
        user_agent: userAgent,
      }).select('id').single()
      if (insertErr) throw new Error(insertErr.message)
      resetRequestId = insertedReset?.id || null
    }

    await logEvent(supabase, {
      event_type: 'community_password_reset_requested',
      community_id: cid,
      actor_email: normalizedEmail,
      actor_role: accountType || null,
      success: !!accountType && publicResetEnabled,
      request_ip: requestIp,
      user_agent: userAgent,
      details: !accountType
        ? { reason: 'account_not_found' }
        : publicResetEnabled
          ? { delivery: 'pending_server_email' }
          : { reason: 'public_password_reset_disabled' },
    })

    return new Response(JSON.stringify({
      ok: true,
      message: 'If the account exists, a reset OTP has been created.',
      resetRequestId: null,
      serverEmailReady: false,
      developmentOtpPreview: null,
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[community-auth-request-reset]', err)
    return new Response(JSON.stringify({ error: 'Unable to create community reset request.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

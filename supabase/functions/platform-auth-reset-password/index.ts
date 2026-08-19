// Supabase Edge Function: platform-auth-reset-password
// Purpose: verify reset OTP server-side, update password, clear platform TOTP
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY
//   PLATFORM_PASSWORD_SALT
//   OTP_HASH_PEPPER

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
  const otpPepper = Deno.env.get('OTP_HASH_PEPPER') || ''
  const publicResetEnabled = Deno.env.get('ENABLE_PUBLIC_PASSWORD_RESET') === 'true'
  const supabase = createClient(supabaseUrl, serviceRoleKey)

  try {
    const { email, otp, newPassword, resetRequestId } = await req.json()
    const normalizedEmail = String(email || '').trim().toLowerCase()
    const cleanOtp = String(otp || '').replace(/\D/g, '')
    const password = String(newPassword || '')
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    if (!publicResetEnabled) {
      await logEvent(supabase, {
        event_type: 'platform_password_reset_completed',
        actor_email: normalizedEmail || null,
        actor_type: null,
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { reason: 'public_password_reset_disabled' },
      })
      return new Response(JSON.stringify({ error: 'Password reset is temporarily disabled. Please contact support.' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!normalizedEmail || cleanOtp.length !== 6 || password.length < 8) {
      return new Response(JSON.stringify({ error: 'Email, valid OTP, and a stronger password are required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const otpHash = await sha256(cleanOtp + otpPepper)
    let resetQuery = supabase
      .from('platform_password_resets')
      .select('*')
      .eq('email', normalizedEmail)
      .is('used_at', null)

    if (resetRequestId) {
      resetQuery = resetQuery.eq('id', String(resetRequestId))
    } else {
      resetQuery = resetQuery.order('created_at', { ascending: false }).limit(5)
    }

    const { data: resetRows, error: resetErr } = await resetQuery

    if (resetErr) throw new Error(resetErr.message)

    const nowIso = new Date().toISOString()
    const resetRow = (resetRows || []).find((row: any) => row.otp_hash === otpHash && row.expires_at > nowIso)

    if (!resetRow) {
      await logEvent(supabase, {
        event_type: 'platform_password_reset_completed',
        actor_email: normalizedEmail,
        actor_type: null,
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { reason: 'invalid_or_expired_otp' },
      })
      return new Response(JSON.stringify({ error: 'Invalid or expired OTP.' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const newHash = await sha256(password + passwordSalt)
    const { data, error } = await supabase.from('platform_kv').select('key, value').in('key', ['admin', 'platformStaffList'])
    if (error) throw new Error(error.message)

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const admin = (rows.admin || {}) as Record<string, unknown>
    const platformStaffList = Array.isArray(rows.platformStaffList) ? rows.platformStaffList as Record<string, unknown>[] : []

    if (resetRow.account_type === 'admin') {
      const updatedAdmin = {
        ...admin,
        password: newHash,
        mustChangePassword: false,
      }
      await supabase.from('platform_kv').upsert({ key: 'admin', value: updatedAdmin })
    } else {
      const updatedStaffList = platformStaffList.map(entry => {
        if (String(entry.email || '').toLowerCase() !== normalizedEmail) return entry
        return {
          ...entry,
          password: newHash,
          mustChangePassword: false,
        }
      })
      await supabase.from('platform_kv').upsert({ key: 'platformStaffList', value: updatedStaffList })
    }

    await supabase.from('platform_sessions').delete().eq('email', normalizedEmail)

    await supabase
      .from('platform_password_resets')
      .update({ used_at: new Date().toISOString() })
      .eq('id', resetRow.id)

    await logEvent(supabase, {
      event_type: 'platform_password_reset_completed',
      actor_email: normalizedEmail,
      actor_type: resetRow.account_type,
      success: true,
      request_ip: requestIp,
      user_agent: userAgent,
      details: { totpCleared: true },
    })

    return new Response(JSON.stringify({
      ok: true,
      message: 'Password reset complete. Google Authenticator setup must be completed again at next login.',
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[platform-auth-reset-password]', err)
    return new Response(JSON.stringify({ error: 'Unable to reset platform password.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

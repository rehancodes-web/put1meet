// Supabase Edge Function: platform-self-change-password
// Purpose: allow the currently authenticated platform user to change their own password
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY
//   PLATFORM_PASSWORD_SALT

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { tokenCandidates } from '../_shared/session.ts'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS') || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com').split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return { 'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session', 'Vary': 'Origin' }
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
  await supabase.from('platform_security_events').insert(payload)
}

async function getRequiredSession(supabase: any, req: Request) {
  const token = req.headers.get('x-platform-session') || ''
  if (!token) return { error: 'Missing platform session.', status: 401 }

  const { data, error } = await supabase.from('platform_sessions').select('*').in('token', await tokenCandidates(token)).maybeSingle()
  if (error) throw new Error(error.message)
  if (!data) return { error: 'Invalid platform session.', status: 401 }
  if (data.expires_at <= new Date().toISOString()) {
    await supabase.from('platform_sessions').delete().eq('token', data.token)
    return { error: 'Platform session expired.', status: 401 }
  }

  return { session: data }
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
    const auth = await getRequiredSession(supabase, req)
    if ('error' in auth) {
      return new Response(JSON.stringify({ error: auth.error }), {
        status: auth.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { newPassword } = await req.json()
    const password = String(newPassword || '')
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    if (password.length < 8) {
      return new Response(JSON.stringify({ error: 'Password must be at least 8 characters.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const session = auth.session
    const normalizedEmail = String(session.email || '').toLowerCase()
    const newHash = await sha256(password + passwordSalt)

    const { data, error } = await supabase.from('platform_kv').select('key, value').in('key', ['admin', 'platformStaffList'])
    if (error) throw new Error(error.message)

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const admin = (rows.admin || {}) as Record<string, unknown>
    const staffList = Array.isArray(rows.platformStaffList) ? rows.platformStaffList as Record<string, unknown>[] : []

    let updated = false

    if (String(admin.email || '').toLowerCase() === normalizedEmail) {
      await supabase.from('platform_kv').upsert({
        key: 'admin',
        value: { ...admin, password: newHash, mustChangePassword: false },
      })
      updated = true
    } else {
      const updatedStaffList = staffList.map((entry) => {
        if (String(entry.email || '').toLowerCase() !== normalizedEmail) return entry
        updated = true
        return { ...entry, password: newHash, mustChangePassword: false }
      })
      if (updated) {
        await supabase.from('platform_kv').upsert({ key: 'platformStaffList', value: updatedStaffList })
      }
    }

    if (!updated) {
      return new Response(JSON.stringify({ error: 'Unable to locate this platform account.' }), {
        status: 404,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    await supabase.from('platform_sessions').update({
      metadata: {
        ...(session.metadata || {}),
        mustChangePassword: false,
      },
    }).eq('token', session.token)

    await logEvent(supabase, {
      event_type: 'platform_password_changed_self',
      actor_email: normalizedEmail,
      actor_type: session.metadata?.accountType || session.role,
      actor_scope: session.scope || 'all',
      success: true,
      request_ip: requestIp,
      user_agent: userAgent,
      details: {},
    })

    return new Response(JSON.stringify({ ok: true, message: 'Password updated.' }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[platform-self-change-password]', err)
    return new Response(JSON.stringify({ error: 'Unable to update platform password.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

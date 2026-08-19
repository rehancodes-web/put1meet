// Supabase Edge Function: community-kv-write
// Purpose: write community_kv rows through authenticated community or platform sessions
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { tokenCandidates } from '../_shared/session.ts'

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

async function getPlatformSession(supabase: any, req: Request) {
  const token = req.headers.get('x-platform-session') || ''
  if (!token) return null
  const { data, error } = await supabase.from('platform_sessions').select('*').in('token', await tokenCandidates(token)).maybeSingle()
  if (error) throw new Error(error.message)
  if (!data) return null
  if (data.expires_at <= new Date().toISOString()) {
    await supabase.from('platform_sessions').delete().eq('token', data.token)
    return null
  }
  return data
}

async function getCommunitySession(supabase: any, req: Request) {
  const token = req.headers.get('x-community-session') || ''
  if (!token) return null
  const { data, error } = await supabase.from('community_sessions').select('*').in('token', await tokenCandidates(token)).maybeSingle()
  if (error) throw new Error(error.message)
  if (!data) return null
  if (data.expires_at <= new Date().toISOString()) {
    await supabase.from('community_sessions').delete().eq('token', data.token)
    return null
  }
  return data
}

async function revalidatePlatformSession(supabase: any, session: any) {
  if (!session) return null
  const { data, error } = await supabase.from('platform_kv').select('key, value').in('key', ['admin', 'platformStaffList'])
  if (error) throw new Error(error.message)
  const rows = Object.fromEntries((data || []).map((row: any) => [row.key, row.value]))
  const email = String(session.email || '').toLowerCase()
  const primary = String(rows.admin?.email || '').toLowerCase() === email
  const staff = (Array.isArray(rows.platformStaffList) ? rows.platformStaffList : [])
    .find((entry: any) => String(entry.email || '').toLowerCase() === email && entry.active !== false)
  if (session.role === 'platform_admin' && !(primary || String(staff?.role || '') === 'superadmin')) return null
  if (session.role === 'platform_staff' && !staff) return null
  return session
}

async function revalidateCommunitySession(supabase: any, session: any) {
  if (!session || session.role !== 'admin') return session
  const { data, error } = await supabase.from('community_kv').select('key, value')
    .eq('community_id', session.community_id).in('key', ['admin', 'staffList'])
  if (error) throw new Error(error.message)
  const rows = Object.fromEntries((data || []).map((row: any) => [row.key, row.value]))
  const email = String(session.email || '').toLowerCase()
  if (String(rows.admin?.email || '').toLowerCase() === email) {
    return { ...session, metadata: { ...(session.metadata || {}), staffRole: 'superadmin' } }
  }
  const staff = (Array.isArray(rows.staffList) ? rows.staffList : [])
    .find((entry: any) => String(entry.email || '').toLowerCase() === email && entry.active !== false)
  if (!staff || String(staff.role || 'staff') !== String(session.metadata?.staffRole || 'staff')) return null
  return session
}

function getClientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown'
}

async function logEvent(supabase: any, payload: Record<string, unknown>) {
  await supabase.from('community_security_events').insert(payload)
}

const USER_WRITABLE_KEYS = new Set([
  'amenityBookings',
  'supportTickets',
  'visitors',
  'payments',
  'activityLogs',
])

const SENSITIVE_KEYS = new Set([
  'admin',
  'staffList',
  'owners',
  'platformStaffList',
  'communities',
])

function isPlatformAdmin(session: Record<string, unknown> | null): boolean {
  return String(session?.role || '') === 'platform_admin'
}

function isCommunityAdmin(session: Record<string, unknown> | null): boolean {
  return String(session?.role || '') === 'admin'
}

function isCommunitySuperAdmin(session: Record<string, unknown> | null): boolean {
  return isCommunityAdmin(session) && String((session?.metadata as Record<string, unknown> | undefined)?.staffRole || '') === 'superadmin'
}

function canWriteCommunityKey(params: {
  platformSession: Record<string, unknown> | null
  communitySession: Record<string, unknown> | null
  key: string
  operation: string
}): boolean {
  const { platformSession, communitySession, key, operation } = params

  if (isPlatformAdmin(platformSession)) return true
  if (isCommunitySuperAdmin(communitySession)) return true
  if (key === 'admin' || key === 'staffList') return false
  if (isCommunityAdmin(communitySession)) return !SENSITIVE_KEYS.has(key)
  if (SENSITIVE_KEYS.has(key)) return false
  if (operation === 'delete') return false

  return String(communitySession?.role || '') === 'user' && USER_WRITABLE_KEYS.has(key)
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (req.method !== 'POST') return new Response('Method not allowed.', { status: 405, headers: corsHeaders })

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const supabase = createClient(supabaseUrl, serviceRoleKey)
    const platformSession = await revalidatePlatformSession(supabase, await getPlatformSession(supabase, req))
    const communitySession = await revalidateCommunitySession(supabase, await getCommunitySession(supabase, req))
    const { communityId, operation, key, value } = await req.json()
    const cid = String(communityId || communitySession?.community_id || '').trim()
    const op = String(operation || 'upsert')
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    if (!cid || !key) {
      return new Response(JSON.stringify({ error: 'Community, key, and operation are required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!platformSession && !communitySession) {
      return new Response(JSON.stringify({ error: 'Missing authorized session.' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (communitySession && String(communitySession.community_id || '') !== cid) {
      return new Response(JSON.stringify({ error: 'Community session does not match the requested community.' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (!canWriteCommunityKey({ platformSession, communitySession, key: String(key), operation: op })) {
      await logEvent(supabase, {
        event_type: 'community_kv_write_denied',
        community_id: cid,
        actor_email: platformSession?.email || communitySession?.email || null,
        actor_role: platformSession ? String(platformSession.role || '') : String(communitySession?.role || ''),
        success: false,
        request_ip: requestIp,
        user_agent: userAgent,
        details: { operation: op, key: String(key), reason: 'insufficient_role' },
      })
      return new Response(JSON.stringify({ error: 'This session is not allowed to write that community data.' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (op === 'delete') {
      const { error } = await supabase.from('community_kv').delete().eq('community_id', cid).eq('key', String(key))
      if (error) throw new Error(error.message)
    } else {
      const { error } = await supabase.from('community_kv').upsert({
        community_id: cid,
        key: String(key),
        value: value ?? null,
      })
      if (error) throw new Error(error.message)
    }

    await logEvent(supabase, {
      event_type: 'community_kv_write',
      community_id: cid,
      actor_email: platformSession?.email || communitySession?.email || null,
      actor_role: platformSession ? String(platformSession.role || 'platform_admin') : String(communitySession?.role || ''),
      success: true,
      request_ip: requestIp,
      user_agent: userAgent,
      details: { operation: op, key: String(key) },
    })

    return new Response(JSON.stringify({ ok: true }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[community-kv-write]', err)
    return new Response(JSON.stringify({ error: 'Unable to write community data.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

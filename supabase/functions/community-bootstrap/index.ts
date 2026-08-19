// Supabase Edge Function: community-bootstrap
// Purpose: load one community's data through an authenticated session token
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

const SECRET_FIELDS = new Set(['password', 'passwordHash', 'totpSecret', 'resetToken', 'resetCode', 'otp'])
const USER_VISIBLE_KEYS = new Set(['owners', 'payments', 'invoices', 'invoiceSettings', 'notices', 'amenities', 'amenityBookings', 'supportTickets', 'visitors'])

function stripSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripSecrets)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .filter(([key]) => !SECRET_FIELDS.has(key))
    .map(([key, nested]) => [key, stripSecrets(nested)]))
}

function belongsToUser(entry: Record<string, unknown>, ownerIds: Set<string>, email: string): boolean {
  const possibleIds = [entry.id, entry.ownerId, entry.owner_id, entry.residentId, entry.resident_id, entry.createdByOwnerId]
    .map((value) => String(value || '')).filter(Boolean)
  if (possibleIds.some((id) => ownerIds.has(id))) return true
  return [entry.email, entry.ownerEmail, entry.residentEmail, entry.createdBy]
    .some((value) => String(value || '').trim().toLowerCase() === email)
}

function sanitizeRows(rows: Array<{ key: string, value: unknown }>, session: any, hasPlatformSession: boolean) {
  if (hasPlatformSession || session?.role === 'admin') {
    return rows.map((row) => ({ ...row, value: stripSecrets(row.value) }))
  }

  const ownerIds = new Set((Array.isArray(session?.metadata?.ownerIds) ? session.metadata.ownerIds : [])
    .map((value: unknown) => String(value)))
  const email = String(session?.email || '').trim().toLowerCase()
  return rows
    .filter((row) => USER_VISIBLE_KEYS.has(row.key))
    .map((row) => {
      if (!Array.isArray(row.value)) return { ...row, value: stripSecrets(row.value) }
      if (row.key === 'notices' || row.key === 'amenities') return { ...row, value: stripSecrets(row.value) }
      const filtered = row.value.filter((entry) => entry && typeof entry === 'object'
        && belongsToUser(entry as Record<string, unknown>, ownerIds, email))
      return { ...row, value: stripSecrets(filtered) }
    })
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
  if (String(rows.admin?.email || '').toLowerCase() === email) return session
  const staff = (Array.isArray(rows.staffList) ? rows.staffList : [])
    .find((entry: any) => String(entry.email || '').toLowerCase() === email && entry.active !== false)
  if (!staff || String(staff.role || 'staff') !== String(session.metadata?.staffRole || 'staff')) return null
  return session
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
    const { communityId } = await req.json().catch(() => ({ communityId: null }))
    const requestedCommunityId = String(communityId || '').trim()

    const platformSession = await revalidatePlatformSession(supabase, await getPlatformSession(supabase, req))
    const communitySession = await revalidateCommunitySession(supabase, await getCommunitySession(supabase, req))

    let cid = requestedCommunityId
    if (communitySession) cid = String(communitySession.community_id || '')
    if (!cid) {
      return new Response(JSON.stringify({ error: 'Community session is required.' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    if (platformSession && platformSession.role === 'platform_staff') {
      const scope = String(platformSession.scope || 'all')
      if (scope !== 'all') {
        const { data: commRow } = await supabase.from('platform_kv').select('value').eq('key', 'communities').maybeSingle()
        const communities = Array.isArray(commRow?.value) ? commRow.value as Record<string, unknown>[] : []
        const community = communities.find((entry) => String(entry.id || '') === cid)
        if (community && String(community.type || 'gated') !== scope) {
          return new Response(JSON.stringify({ error: 'This platform staff session cannot access that community.' }), {
            status: 403,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          })
        }
      }
    }

    if (!platformSession && !communitySession) {
      return new Response(JSON.stringify({ error: 'Missing authorized session.' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { data, error } = await supabase
      .from('community_kv')
      .select('key, value')
      .eq('community_id', cid)

    if (error) throw new Error(error.message)

    const { data: commRow, error: commErr } = await supabase
      .from('platform_kv')
      .select('value')
      .eq('key', 'communities')
      .maybeSingle()

    if (commErr) throw new Error(commErr.message)
    const communities = Array.isArray(commRow?.value) ? commRow.value as Record<string, unknown>[] : []
    const community = communities.find((entry) => String(entry.id || '') === cid) || null

    return new Response(JSON.stringify({
      ok: true,
      communityId: cid,
      community,
      rows: sanitizeRows(data || [], communitySession, !!platformSession),
      session: communitySession ? {
        email: communitySession.email,
        role: communitySession.role,
        metadata: communitySession.metadata,
        mustChangePassword: !!communitySession.metadata?.mustChangePassword,
        expiresAt: communitySession.expires_at,
      } : null,
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[community-bootstrap]', err)
    return new Response(JSON.stringify({ error: 'Unable to load community data.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

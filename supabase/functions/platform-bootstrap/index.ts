// Supabase Edge Function: platform-bootstrap
// Purpose: provide sanitized platform bootstrap data without exposing platform_kv directly
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { tokenCandidates } from '../_shared/session.ts'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS') || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com').split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return { 'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session', 'Vary': 'Origin' }
}

async function getPlatformSession(supabase: any, req: Request) {
  const token = req.headers.get('x-platform-session') || ''
  if (!token) return null

  const { data, error } = await supabase
    .from('platform_sessions')
    .select('*')
    .in('token', await tokenCandidates(token))
    .maybeSingle()

  if (error) throw new Error(error.message)
  if (!data) return null
  if (data.expires_at <= new Date().toISOString()) {
    await supabase.from('platform_sessions').delete().eq('token', data.token)
    return null
  }
  return data
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method !== 'POST' && req.method !== 'OPTIONS') return new Response('Method not allowed.', { status: 405, headers: corsHeaders })
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const supabase = createClient(supabaseUrl, serviceRoleKey)
    const session = await getPlatformSession(supabase, req)

    const keys = session?.role === 'platform_admin'
      ? ['communities', 'platformStaffList', 'admin']
      : ['communities']

    const { data, error } = await supabase
      .from('platform_kv')
      .select('key, value')
      .in('key', keys)

    if (error) throw new Error(error.message)

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const communities = Array.isArray(rows.communities) ? rows.communities as Record<string, unknown>[] : []
    const adminRow = (rows.admin || null) as Record<string, unknown> | null
    const sessionScope = String(session?.scope || 'all')
    const filteredCommunities = communities.filter((entry) => {
      if (!session || sessionScope === 'all') return true
      return String(entry.type || 'gated') === sessionScope
    })

    const sanitizedCommunities = filteredCommunities.map((entry) => ({
      id: entry.id,
      slug: entry.slug,
      name: entry.name,
      address: session ? (entry.address || '') : '',
      adminEmail: session ? (entry.adminEmail || '') : '',
      type: entry.type || 'gated',
      createdAt: entry.createdAt || null,
    }))

    const platformStaffList = session?.role === 'platform_admin' && Array.isArray(rows.platformStaffList)
      ? rows.platformStaffList.map((entry: Record<string, unknown>) => ({
          id: entry.id,
          name: entry.name || '',
          email: entry.email || '',
          role: entry.role || 'developer',
          scope: entry.scope || 'all',
          active: entry.active !== false,
          totpSecret: !!entry.totpSecret,
          totpVerified: entry.totpVerified !== false,
        }))
      : []

    const admin = session?.role === 'platform_admin' && adminRow
      ? {
          email: adminRow.email || '',
          name: adminRow.name || 'Platform Admin',
          totpSecret: !!adminRow.totpSecret,
          totpVerified: adminRow.totpVerified !== false,
        }
      : null

    return new Response(JSON.stringify({
      ok: true,
      communities: sanitizedCommunities,
      session: session ? {
        email: session.email,
        role: session.role,
        scope: session.scope,
        platformRole: session.metadata?.platformRole || null,
        mustChangePassword: !!session.metadata?.mustChangePassword,
        expiresAt: session.expires_at,
      } : null,
      admin,
      platformStaffList,
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[platform-bootstrap]', err)
    return new Response(JSON.stringify({ error: 'Unable to load platform bootstrap data.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

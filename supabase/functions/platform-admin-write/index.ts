// Supabase Edge Function: platform-admin-write
// Purpose: handle privileged All Communities Dashboard writes server-side
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY
//   PLATFORM_PASSWORD_SALT

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
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session',
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
  await supabase.from('platform_security_events').insert(payload)
}

async function getRequiredAdminSession(supabase: any, req: Request) {
  const token = req.headers.get('x-platform-session') || ''
  if (!token) {
    return { error: 'Missing platform session.', status: 401 }
  }

  const { data, error } = await supabase
    .from('platform_sessions')
    .select('*')
    .in('token', await tokenCandidates(token))
    .maybeSingle()

  if (error) throw new Error(error.message)
  if (!data) return { error: 'Invalid platform session.', status: 401 }
  if (data.expires_at <= new Date().toISOString()) {
    await supabase.from('platform_sessions').delete().eq('token', data.token)
    return { error: 'Platform session expired.', status: 401 }
  }
  if (data.role !== 'platform_admin') {
    return { error: 'Only the platform super admin can perform this action.', status: 403 }
  }

  return { session: data }
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const passwordSalt = Deno.env.get('PLATFORM_PASSWORD_SALT') || ''
  const supabase = createClient(supabaseUrl, serviceRoleKey)

  try {
    const auth = await getRequiredAdminSession(supabase, req)
    if ('error' in auth) {
      return new Response(JSON.stringify({ error: auth.error }), {
        status: auth.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { action, payload = {} } = await req.json()
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    const { data, error } = await supabase
      .from('platform_kv')
      .select('key, value')
      .in('key', ['admin', 'platformStaffList', 'communities'])

    if (error) throw new Error(error.message)

    const rows = Object.fromEntries((data || []).map((row: { key: string, value: unknown }) => [row.key, row.value]))
    const admin = (rows.admin || {}) as Record<string, unknown>
    const staffList = Array.isArray(rows.platformStaffList) ? rows.platformStaffList as Record<string, unknown>[] : []
    const communities = Array.isArray(rows.communities) ? rows.communities as Record<string, unknown>[] : []

    let responsePayload: Record<string, unknown> = { ok: true }

    if (action === 'reset_admin_2fa') {
      await supabase.from('platform_kv').upsert({
        key: 'admin',
        value: { ...admin, totpSecret: null, totpVerified: false },
      })
    } else if (action === 'reset_staff_2fa') {
      const staffId = String(payload.staffId || '')
      const updated = staffList.map((entry) => {
        if (String(entry.id || '') !== staffId) return entry
        return { ...entry, totpSecret: null, totpVerified: false }
      })
      await supabase.from('platform_kv').upsert({ key: 'platformStaffList', value: updated })
    } else if (action === 'set_password') {
      const targetType = String(payload.targetType || '')
      const targetId = String(payload.targetId || '')
      const password = String(payload.password || '')
      if (password.length < 8) {
        return new Response(JSON.stringify({ error: 'Password must be at least 8 characters.' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
      const passwordHash = await sha256(password + passwordSalt)
      if (targetType === 'admin') {
        await supabase.from('platform_kv').upsert({
          key: 'admin',
          value: { ...admin, password: passwordHash, mustChangePassword: true },
        })
      } else if (targetType === 'staff') {
        const updated = staffList.map((entry) => {
          if (String(entry.id || '') !== targetId) return entry
          return { ...entry, password: passwordHash, mustChangePassword: true }
        })
        await supabase.from('platform_kv').upsert({ key: 'platformStaffList', value: updated })
      } else {
        return new Response(JSON.stringify({ error: 'Invalid platform user selected for password reset.' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }
    } else if (action === 'upsert_staff') {
      const staff = (payload.staff || {}) as Record<string, unknown>
      const id = String(staff.id || '')
      const name = String(staff.name || '').trim()
      const email = String(staff.email || '').trim().toLowerCase()
      const role = String(staff.role || 'developer')
      const scope = role === 'superadmin' ? 'all' : String(staff.scope || 'all')
      const active = staff.active !== false
      const password = String(payload.password || '')

      if (!name || !email) {
        return new Response(JSON.stringify({ error: 'Staff name and email are required.' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      const duplicate = email === String(admin.email || '').toLowerCase()
        || staffList.some((entry) => String(entry.email || '').toLowerCase() === email && String(entry.id || '') !== id)
      if (duplicate) {
        return new Response(JSON.stringify({ error: 'This email is already in use.' }), {
          status: 409,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      const passwordHash = password ? await sha256(password + passwordSalt) : null
      let updatedList: Record<string, unknown>[] = []
      if (id) {
        updatedList = staffList.map((entry) => {
          if (String(entry.id || '') !== id) return entry
          return {
            ...entry,
            name,
            email,
            role,
            scope,
            active,
            ...(passwordHash ? { password: passwordHash, mustChangePassword: true, totpSecret: null, totpVerified: false } : {}),
          }
        })
      } else {
        if (!passwordHash) {
          return new Response(JSON.stringify({ error: 'Password is required for new platform staff.' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          })
        }
        updatedList = [...staffList, {
          id: `pst${Date.now()}`,
          name,
          email,
          role,
          scope,
          active,
          password: passwordHash,
          mustChangePassword: true,
          createdAt: Date.now(),
          totpSecret: null,
          totpVerified: false,
        }]
      }
      await supabase.from('platform_kv').upsert({ key: 'platformStaffList', value: updatedList })
    } else if (action === 'delete_staff') {
      const staffId = String(payload.staffId || '')
      await supabase.from('platform_kv').upsert({
        key: 'platformStaffList',
        value: staffList.filter((entry) => String(entry.id || '') !== staffId),
      })
    } else if (action === 'upsert_community') {
      const community = (payload.community || {}) as Record<string, unknown>
      const id = String(community.id || '')
      const name = String(community.name || '').trim()
      const slug = String(community.slug || '').trim()
      const address = String(community.address || '').trim()
      const adminEmail = String(community.adminEmail || '').trim().toLowerCase()
      const type = String(community.type || 'gated')
      const password = String(payload.adminPassword || '')

      if (!name || !slug || !adminEmail) {
        return new Response(JSON.stringify({ error: 'Community name, slug, and admin email are required.' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      const duplicateSlug = communities.some((entry) => String(entry.slug || '') === slug && String(entry.id || '') !== id)
      if (duplicateSlug) {
        return new Response(JSON.stringify({ error: 'Community slug already exists.' }), {
          status: 409,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        })
      }

      let communityId = id
      let nextCommunities: Record<string, unknown>[]

      if (id) {
        nextCommunities = communities.map((entry) => {
          if (String(entry.id || '') !== id) return entry
          return { ...entry, name, slug, address, adminEmail, type }
        })
      } else {
        communityId = `comm_${Date.now().toString(36)}`
        nextCommunities = [...communities, {
          id: communityId,
          name,
          slug,
          address,
          adminEmail,
          type,
          createdAt: Date.now(),
        }]
      }

      await supabase.from('platform_kv').upsert({ key: 'communities', value: nextCommunities })

      const { data: adminRow, error: adminRowError } = await supabase
        .from('community_kv')
        .select('value')
        .eq('community_id', communityId)
        .eq('key', 'admin')
        .maybeSingle()

      if (adminRowError) throw new Error(adminRowError.message)

      const initialRows = Array.isArray(payload.initialRows) ? payload.initialRows as Record<string, unknown>[] : []
      if (!id && initialRows.length) {
        const seedRows = initialRows.map((row) => ({
          community_id: communityId,
          key: String(row.key || ''),
          value: row.value ?? null,
        })).filter((row) => row.key)
        if (seedRows.length) {
          const { error: seedErr } = await supabase.from('community_kv').upsert(seedRows)
          if (seedErr) throw new Error(seedErr.message)
        }
      }

      if (password || !adminRow?.value) {
        const passwordHash = password ? await sha256(password + passwordSalt) : null
        const mergedAdmin = {
          ...(adminRow?.value || {}),
          email: adminEmail,
          ...(passwordHash ? { password: passwordHash, mustChangePassword: true } : {}),
        }
        await supabase.from('community_kv').upsert({
          community_id: communityId,
          key: 'admin',
          value: mergedAdmin,
        })
      }

      responsePayload.communityId = communityId
    } else if (action === 'delete_community') {
      const communityId = String(payload.communityId || '')
      await supabase.from('community_kv').delete().eq('community_id', communityId)
      await supabase.from('platform_kv').upsert({
        key: 'communities',
        value: communities.filter((entry) => String(entry.id || '') !== communityId),
      })
    } else {
      return new Response(JSON.stringify({ error: 'Unsupported platform admin action.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    await logEvent(supabase, {
      event_type: 'platform_admin_write',
      actor_email: auth.session.email,
      actor_type: 'admin',
      actor_scope: 'all',
      success: true,
      request_ip: requestIp,
      user_agent: userAgent,
      details: { action },
    })

    return new Response(JSON.stringify(responsePayload), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[platform-admin-write]', err)
    return new Response(JSON.stringify({ error: 'Unable to complete platform admin action.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

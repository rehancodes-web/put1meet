// Supabase Edge Function: community-ai-assistant
// Purpose: AI assistance for reconciliation, expense categorization, and finance summaries
//
// Required secrets:
//   SUPABASE_SERVICE_ROLE_KEY
//   OPENAI_API_KEY
//
// Optional secrets:
//   OPENAI_AI_MODEL (defaults to gpt-5.4-mini)

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { tokenCandidates } from '../_shared/session.ts'

const ALLOWED_ORIGINS = new Set((Deno.env.get('ALLOWED_WEB_ORIGINS') || 'https://ourcommunity.it.com,https://www.ourcommunity.it.com').split(',').map((value) => value.trim()).filter(Boolean))
function corsHeadersFor(req: Request) {
  const origin = req.headers.get('origin') || ''
  return { 'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://ourcommunity.it.com', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-platform-session, x-community-session', 'Vary': 'Origin' }
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

function getClientIp(req: Request): string {
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || req.headers.get('x-real-ip')
    || 'unknown'
}

function extractOutputText(data: any): string {
  if (typeof data?.output_text === 'string' && data.output_text.trim()) return data.output_text.trim()
  const textParts: string[] = []
  for (const item of data?.output || []) {
    for (const content of item?.content || []) {
      if (content?.type === 'output_text' && content?.text) textParts.push(String(content.text))
    }
  }
  return textParts.join('\n').trim()
}

function safeJsonParse(text: string) {
  const cleaned = text.replace(/```json|```/gi, '').trim()
  const firstBrace = cleaned.indexOf('{')
  const lastBrace = cleaned.lastIndexOf('}')
  const jsonText = firstBrace >= 0 && lastBrace >= 0 ? cleaned.slice(firstBrace, lastBrace + 1) : cleaned
  return JSON.parse(jsonText)
}

async function callOpenAI(systemPrompt: string, userPayload: Record<string, unknown>) {
  const apiKey = Deno.env.get('OPENAI_API_KEY')
  const model = Deno.env.get('OPENAI_AI_MODEL') || 'gpt-5.4-mini'
  if (!apiKey) throw new Error('OPENAI_API_KEY is not configured.')

  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0.1,
      input: [
        { role: 'system', content: [{ type: 'input_text', text: systemPrompt }] },
        { role: 'user', content: [{ type: 'input_text', text: JSON.stringify(userPayload) }] },
      ],
    }),
  })

  const data = await response.json()
  if (!response.ok) {
    throw new Error(data?.error?.message || 'OpenAI request failed.')
  }
  return safeJsonParse(extractOutputText(data))
}

function expenseHeadPrompt() {
  return [
    'You are an accounting assistant for a housing/community ERP.',
    'The input has already been privacy-sanitized. Never ask for names, phone numbers, or emails.',
    'Choose the single best expense head from the provided list.',
    'Return strict JSON only in this shape:',
    '{"suggestion":{"headId":"string or empty","headName":"string","confidence":0.0,"reason":"short explanation"}}',
    'Confidence must be between 0 and 1.',
    'If uncertain, keep confidence low and still provide the closest best fit.',
  ].join(' ')
}

function reconciliationPrompt() {
  return [
    'You are a reconciliation assistant for a community ERP.',
    'The data is privacy-sanitized. Use only unit references, invoice ids, periods, amounts, and statement narration.',
    'For each statement line, suggest zero, one, or multiple likely invoice matches.',
    'Prefer exact amount and unit reference matches. Consider split matches only when totals align strongly.',
    'Return strict JSON only in this shape:',
    '{"suggestions":[{"lineNumber":1,"status":"matched|review|no_match","confidence":0.0,"reason":"short explanation","matches":[{"invoiceId":"...","unitRef":"...","amountDue":0}]}]}',
    'Keep matches short. If there is no strong match, use status "review" or "no_match".',
  ].join(' ')
}

function financeSummaryPrompt() {
  return [
    'You are a finance analyst for a housing/community ERP.',
    'The data is aggregated and sanitized. Do not ask for personal data.',
    'Write a concise plain-language summary for admins.',
    'Return strict JSON only in this shape:',
    '{"summary":{"overview":"2-3 sentence summary","highlights":["..."],"recommendedActions":["..."]}}',
    'Highlights should be short bullets, maximum 4.',
    'Recommended actions should be practical and conservative, maximum 4.',
  ].join(' ')
}

serve(async (req) => {
  const corsHeaders = corsHeadersFor(req)
  const origin = req.headers.get('origin') || ''
  if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response('Forbidden origin.', { status: 403, headers: corsHeaders })
  if (req.method !== 'POST' && req.method !== 'OPTIONS') return new Response('Method not allowed.', { status: 405, headers: corsHeaders })
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const supabase = createClient(supabaseUrl, serviceRoleKey)
    const platformSession = await getPlatformSession(supabase, req)
    const communitySession = await getCommunitySession(supabase, req)
    const requestIp = getClientIp(req)
    const userAgent = req.headers.get('user-agent') || ''

    if (!platformSession && !communitySession) {
      return new Response(JSON.stringify({ error: 'Missing authorized session.' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    const { action, communityId, payload } = await req.json()
    const cid = String(communityId || communitySession?.community_id || '').trim()
    if (!cid) {
      return new Response(JSON.stringify({ error: 'Community id is required.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }
    if (communitySession && String(communitySession.community_id || '') !== cid) {
      return new Response(JSON.stringify({ error: 'Community session does not match the requested community.' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    let result: Record<string, unknown>
    if (action === 'suggest_expense_head') {
      result = await callOpenAI(expenseHeadPrompt(), payload || {})
    } else if (action === 'reconcile_payments') {
      result = await callOpenAI(reconciliationPrompt(), payload || {})
    } else if (action === 'monthly_summary') {
      result = await callOpenAI(financeSummaryPrompt(), payload || {})
    } else {
      return new Response(JSON.stringify({ error: 'Unsupported AI action.' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      })
    }

    await supabase.from('community_security_events').insert({
      event_type: 'community_ai_assistant',
      community_id: cid,
      actor_email: platformSession?.email || communitySession?.email || null,
      actor_role: platformSession ? String(platformSession.role || 'platform_admin') : String(communitySession?.role || ''),
      success: true,
      request_ip: requestIp,
      user_agent: userAgent,
      details: { action: String(action || '') },
    })

    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  } catch (err) {
    console.error('[community-ai-assistant]', err)
    return new Response(JSON.stringify({ error: err instanceof Error ? err.message : 'Unable to process AI request.' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
  }
})

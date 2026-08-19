import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.57.4";

type JsonMap = Record<string, unknown>;
type Owner = JsonMap & { id?: string; name?: string; mobile?: string; whatsappOptIn?: boolean; smsOptIn?: boolean };
type Invoice = JsonMap & { id?: string; ownerId?: string; amount?: number; penalty?: number; paidAmount?: number; dueDate?: string; status?: string };

const MSG91_SMS_URL = "https://control.msg91.com/api/v5/flow";
const MSG91_WHATSAPP_URL = "https://control.msg91.com/api/v5/whatsapp/whatsapp-outbound-message/bulk/";

function requiredEnv(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`Missing required secret: ${name}`);
  return value;
}

function booleanEnv(name: string, fallback: boolean): boolean {
  const value = Deno.env.get(name)?.trim().toLowerCase();
  return value == null || value === "" ? fallback : value === "true";
}

function indiaMobile(value: unknown): string | null {
  const digits = String(value ?? "").replace(/\D/g, "");
  if (/^[6-9]\d{9}$/.test(digits)) return `91${digits}`;
  if (/^91[6-9]\d{9}$/.test(digits)) return digits;
  return null;
}

function outstanding(invoice: Invoice): number {
  const total = Number(invoice.amount || 0) + Number(invoice.penalty || 0);
  return Math.max(0, Math.round((total - Number(invoice.paidAmount || 0)) * 100) / 100);
}

function dueFingerprint(invoices: Invoice[]): string {
  return invoices
    .map((invoice) => `${invoice.id || "unknown"}:${outstanding(invoice).toFixed(2)}`)
    .sort()
    .join("|");
}

function jsonResponse(body: JsonMap, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

async function msg91Post(url: string, authKey: string, body: JsonMap): Promise<JsonMap> {
  const response = await fetch(url, {
    method: "POST",
    headers: { accept: "application/json", authkey: authKey, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let payload: JsonMap = {};
  try { payload = text ? JSON.parse(text) : {}; } catch { payload = { response: text.slice(0, 500) }; }
  if (!response.ok) throw new Error(`MSG91 returned HTTP ${response.status}`);
  return payload;
}

Deno.serve(async (request) => {
  if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  try {
    const cronSecret = requiredEnv("DUE_REMINDER_CRON_SECRET");
    if (request.headers.get("x-cron-secret") !== cronSecret) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const body = await request.json().catch(() => ({})) as JsonMap;
    const dryRun = body.dryRun !== false;
    const communityFilter = typeof body.communityId === "string" ? body.communityId : null;
    const today = new Date().toISOString().slice(0, 10);
    const authKey = dryRun ? "" : requiredEnv("MSG91_AUTH_KEY");
    const smsTemplateId = dryRun ? "" : requiredEnv("MSG91_SMS_TEMPLATE_ID");
    const whatsappNumber = dryRun ? "" : requiredEnv("MSG91_WHATSAPP_INTEGRATED_NUMBER");
    const whatsappTemplate = dryRun ? "" : requiredEnv("MSG91_WHATSAPP_TEMPLATE_NAME");
    const whatsappLanguage = Deno.env.get("MSG91_WHATSAPP_TEMPLATE_LANGUAGE")?.trim() || "en";
    const requireOptIn = booleanEnv("DUE_REMINDER_REQUIRE_OPT_IN", true);

    const supabase = createClient(requiredEnv("SUPABASE_URL"), requiredEnv("SUPABASE_SERVICE_ROLE_KEY"), {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    let communitiesQuery = supabase.from("platform_kv").select("value").eq("key", "communities").single();
    const { data: communitiesRow, error: communitiesError } = await communitiesQuery;
    if (communitiesError) throw communitiesError;
    let communities = Array.isArray(communitiesRow?.value) ? communitiesRow.value as JsonMap[] : [];
    if (communityFilter) communities = communities.filter((community) => community.id === communityFilter);

    const summary = { dryRun, communities: communities.length, candidates: 0, whatsappSent: 0, smsSent: 0, skipped: 0, failed: 0 };

    for (const community of communities) {
      const communityId = String(community.id || "");
      if (!communityId) continue;
      const { data: rows, error } = await supabase
        .from("community_kv")
        .select("key,value")
        .eq("community_id", communityId)
        .in("key", ["owners", "invoices"]);
      if (error) throw error;

      const owners = ((rows || []).find((row) => row.key === "owners")?.value || []) as Owner[];
      const invoices = ((rows || []).find((row) => row.key === "invoices")?.value || []) as Invoice[];

      for (const owner of owners) {
        const ownerId = String(owner.id || "");
        const mobile = indiaMobile(owner.mobile);
        if (!ownerId || !mobile) { summary.skipped++; continue; }

        const pending = invoices.filter((invoice) =>
          invoice.ownerId === ownerId && invoice.status !== "paid" && outstanding(invoice) > 0
        );
        if (!pending.length) continue;
        summary.candidates++;

        const amount = pending.reduce((sum, invoice) => sum + outstanding(invoice), 0);
        const overdueCount = pending.filter((invoice) => invoice.dueDate && invoice.dueDate < today).length;
        const variables = {
          name: String(owner.name || "Resident").slice(0, 80),
          community: String(community.name || "Your community").slice(0, 100),
          amount: amount.toFixed(2),
          invoice_count: String(pending.length),
          overdue_count: String(overdueCount),
        };
        const fingerprint = dueFingerprint(pending);

        const channels = [
          { name: "whatsapp", allowed: !requireOptIn || owner.whatsappOptIn === true },
          { name: "sms", allowed: !requireOptIn || owner.smsOptIn === true },
        ];

        for (const channel of channels) {
          if (!channel.allowed) { summary.skipped++; continue; }
          if (dryRun) continue;
          const ledger = { community_id: communityId, owner_id: ownerId, channel: channel.name, reminder_date: today, dues_fingerprint: fingerprint };
          const { data: claimed, error: claimError } = await supabase
            .from("notification_delivery_log")
            .insert({ ...ledger, status: "processing" })
            .select("id")
            .maybeSingle();
          if (claimError?.code === "23505") { summary.skipped++; continue; }
          if (claimError) throw claimError;

          try {
            let providerResponse: JsonMap;
            if (channel.name === "sms") {
              providerResponse = await msg91Post(MSG91_SMS_URL, authKey, {
                template_id: smsTemplateId,
                short_url: "0",
                realTimeResponse: "1",
                recipients: [{ mobiles: mobile, VAR1: variables.name, VAR2: variables.community, VAR3: variables.amount, VAR4: variables.invoice_count }],
              });
              summary.smsSent++;
            } else {
              providerResponse = await msg91Post(MSG91_WHATSAPP_URL, authKey, {
                integrated_number: whatsappNumber,
                content_type: "template",
                payload: {
                  type: "template",
                  template: {
                    name: whatsappTemplate,
                    language: { code: whatsappLanguage, policy: "deterministic" },
                    to_and_components: [{
                      to: [mobile],
                      components: {
                        body_1: { type: "text", value: variables.name },
                        body_2: { type: "text", value: variables.community },
                        body_3: { type: "text", value: variables.amount },
                        body_4: { type: "text", value: variables.invoice_count },
                      },
                    }],
                  },
                },
              });
              summary.whatsappSent++;
            }
            await supabase.from("notification_delivery_log").update({ status: "accepted", provider_response: providerResponse, sent_at: new Date().toISOString() }).eq("id", claimed!.id);
          } catch (error) {
            summary.failed++;
            await supabase.from("notification_delivery_log").update({ status: "failed", error_code: error instanceof Error ? error.message.slice(0, 250) : "Provider request failed" }).eq("id", claimed!.id);
          }
        }
      }
    }

    return jsonResponse(summary);
  } catch (error) {
    console.error("due-reminder-run-failed", error instanceof Error ? error.message : "unknown error");
    return jsonResponse({ error: "Reminder run failed" }, 500);
  }
});

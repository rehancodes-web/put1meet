import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.57.4";

type JsonMap = Record<string, unknown>;
const DEFAULT_ORIGINS = ["https://ourcommunity.it.com", "https://www.ourcommunity.it.com"];

function allowedOrigins(): Set<string> {
  const values = (Deno.env.get("ALLOWED_ORIGINS") || "").split(",").map((v) => v.trim()).filter(Boolean);
  return new Set(values.length ? values : DEFAULT_ORIGINS);
}
function cors(req: Request): HeadersInit {
  const origin = req.headers.get("origin") || "";
  return {
    "access-control-allow-origin": allowedOrigins().has(origin) ? origin : DEFAULT_ORIGINS[0],
    "access-control-allow-headers": "authorization, apikey, content-type, x-client-info, x-community-session",
    "access-control-allow-methods": "POST, OPTIONS",
    "vary": "Origin",
  };
}
function json(req: Request, body: JsonMap, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors(req), "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
function env(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}
async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}
function outstanding(invoice: JsonMap): number {
  const total = Number(invoice.amount || 0) + Number(invoice.penalty || 0);
  return Math.max(0, Math.round((total - Number(invoice.paidAmount || 0)) * 100) / 100);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== "POST") return json(req, { error: "Method not allowed" }, 405);
  if (!allowedOrigins().has(req.headers.get("origin") || "")) return json(req, { error: "Origin not allowed" }, 403);

  try {
    const db = createClient(env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY"), {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const body = await req.json().catch(() => ({})) as JsonMap;
    const communityId = String(body.communityId || "").trim();
    const invoiceId = String(body.invoiceId || "").trim();
    const ownerId = String(body.ownerId || "").trim();
    const token = (req.headers.get("x-community-session") || "").trim();
    if (!communityId || !invoiceId || !ownerId || !token) {
      return json(req, { error: "A valid session, community, owner, and invoice are required." }, 400);
    }
    if ([communityId, invoiceId, ownerId].some((v) => v.length > 160)) return json(req, { error: "Invalid identifier." }, 400);

    const tokenHash = await sha256(token);
    const { data: session, error: sessionError } = await db.from("community_sessions")
      .select("community_id,role,metadata,expires_at").in("token", [tokenHash, token]).maybeSingle();
    if (sessionError) throw sessionError;
    if (!session || session.expires_at <= new Date().toISOString()) return json(req, { error: "Session expired." }, 401);
    if (String(session.community_id) !== communityId) return json(req, { error: "Community access denied." }, 403);

    const ownerIds = Array.isArray(session.metadata?.ownerIds) ? session.metadata.ownerIds.map(String) : [];
    if (session.role !== "admin" && (session.role !== "user" || !ownerIds.includes(ownerId))) {
      return json(req, { error: "Invoice access denied." }, 403);
    }

    const { data: row, error: rowError } = await db.from("community_kv").select("value")
      .eq("community_id", communityId).eq("key", "invoices").maybeSingle();
    if (rowError) throw rowError;
    const invoices = Array.isArray(row?.value) ? row.value as JsonMap[] : [];
    const invoice = invoices.find((item) => String(item.id || "") === invoiceId);
    if (!invoice || String(invoice.ownerId || "") !== ownerId) return json(req, { error: "Invoice not found." }, 404);
    const amountPaise = Math.round(outstanding(invoice) * 100);
    if (!Number.isSafeInteger(amountPaise) || amountPaise <= 0) return json(req, { error: "This invoice has no payable balance." }, 409);

    const keyId = env("RAZORPAY_KEY_ID");
    const keySecret = env("RAZORPAY_KEY_SECRET");
    const provider = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: { authorization: `Basic ${btoa(`${keyId}:${keySecret}`)}`, "content-type": "application/json" },
      body: JSON.stringify({
        amount: amountPaise,
        currency: "INR",
        receipt: invoiceId.slice(0, 40),
        notes: { invoiceId, ownerId, communityId },
      }),
    });
    const order = await provider.json().catch(() => ({})) as JsonMap;
    if (!provider.ok || typeof order.id !== "string") throw new Error("provider_order_failed");

    const { error: ledgerError } = await db.from("payment_orders").insert({
      razorpay_order_id: order.id,
      community_id: communityId,
      invoice_id: invoiceId,
      owner_id: ownerId,
      amount_paise: amountPaise,
      currency: "INR",
    });
    if (ledgerError) throw ledgerError;
    return json(req, { orderId: order.id, amount: amountPaise, currency: "INR", keyId });
  } catch (error) {
    console.error("razorpay-order-failed", error instanceof Error ? error.message : "unknown");
    return json(req, { error: "Unable to create a payment order." }, 500);
  }
});

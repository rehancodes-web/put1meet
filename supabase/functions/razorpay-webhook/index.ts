import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.57.4";

type JsonMap = Record<string, unknown>;
function env(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}
async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}
async function verifySignature(body: string, signature: string, secret: string): Promise<boolean> {
  if (!signature || !secret || !/^[a-f\d]{64}$/i.test(signature)) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const bytes = new Uint8Array(signature.match(/.{2}/g)!.map((hex) => Number.parseInt(hex, 16)));
  return crypto.subtle.verify("HMAC", key, bytes, new TextEncoder().encode(body));
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const rawBody = await req.text();
  const signature = req.headers.get("x-razorpay-signature") || "";
  if (!await verifySignature(rawBody, signature, env("RAZORPAY_WEBHOOK_SECRET"))) {
    return new Response("Invalid signature", { status: 400 });
  }

  let event: JsonMap;
  try { event = JSON.parse(rawBody) as JsonMap; } catch { return new Response("Invalid payload", { status: 400 }); }
  if (event.event !== "payment.captured") return new Response("ok", { status: 200 });

  const entity = ((event.payload as JsonMap)?.payment as JsonMap)?.entity as JsonMap | undefined;
  const paymentId = String(entity?.id || "");
  const orderId = String(entity?.order_id || "");
  const eventId = String(event.id || `payment:${paymentId}`);
  if (!paymentId || !orderId) return new Response("Missing payment identity", { status: 400 });

  const db = createClient(env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY"), {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { error: claimError } = await db.from("payment_events").insert({
    event_id: eventId,
    razorpay_payment_id: paymentId,
    razorpay_order_id: orderId,
    payload_sha256: await sha256(rawBody),
  });
  if (claimError?.code === "23505") return new Response("ok", { status: 200 });
  if (claimError) return new Response("Unable to claim event", { status: 500 });

  try {
    const { data: order, error: orderError } = await db.from("payment_orders").select("*")
      .eq("razorpay_order_id", orderId).maybeSingle();
    if (orderError) throw orderError;
    if (!order || order.status !== "created") throw new Error("unknown_or_closed_order");
    if (String(entity?.status || "") !== "captured" || String(entity?.currency || "") !== "INR") {
      throw new Error("invalid_payment_state");
    }
    if (Number(entity?.amount) !== Number(order.amount_paise)) throw new Error("amount_mismatch");
    const notes = (entity?.notes || {}) as JsonMap;
    if (
      String(notes.communityId || "") !== order.community_id ||
      String(notes.invoiceId || "") !== order.invoice_id ||
      String(notes.ownerId || "") !== order.owner_id
    ) throw new Error("order_binding_mismatch");

    const { data: rows, error: rowsError } = await db.from("community_kv").select("key,value")
      .eq("community_id", order.community_id).in("key", ["invoices", "payments"]);
    if (rowsError) throw rowsError;
    const invoices = (((rows || []).find((row) => row.key === "invoices")?.value) || []) as JsonMap[];
    const payments = (((rows || []).find((row) => row.key === "payments")?.value) || []) as JsonMap[];
    if (payments.some((payment) => payment.razorpayPaymentId === paymentId)) {
      await db.from("payment_events").update({ status: "duplicate", processed_at: new Date().toISOString() }).eq("event_id", eventId);
      return new Response("ok", { status: 200 });
    }

    const index = invoices.findIndex((invoice) =>
      String(invoice.id || "") === order.invoice_id && String(invoice.ownerId || "") === order.owner_id
    );
    if (index < 0) throw new Error("invoice_not_found");
    const invoice = invoices[index];
    const amount = Number(order.amount_paise) / 100;
    const paid = Number(invoice.paidAmount || 0) + amount;
    const due = Number(invoice.amount || 0) + Number(invoice.penalty || 0);
    const date = new Date(Number(entity?.created_at || 0) * 1000).toISOString().slice(0, 10);
    invoices[index] = {
      ...invoice,
      paidAmount: paid,
      status: paid >= due ? "paid" : "partial",
      paidDate: paid >= due ? date : (invoice.paidDate || null),
      paymentId: paid >= due ? `rzp_${paymentId}` : (invoice.paymentId || null),
    };
    payments.push({
      id: `rzp_${paymentId}`,
      ownerId: order.owner_id,
      month: invoice.month,
      year: invoice.year,
      amount,
      date,
      mode: "razorpay",
      notes: `Razorpay ${paymentId}`,
      razorpayPaymentId: paymentId,
      razorpayOrderId: orderId,
      invoiceAdjustments: [{ invId: order.invoice_id, amount }],
      createdAt: Date.now(),
    });

    const invoiceWrite = await db.from("community_kv").upsert({
      community_id: order.community_id,
      key: "invoices",
      value: invoices,
    });
    if (invoiceWrite.error) throw invoiceWrite.error;
    const paymentWrite = await db.from("community_kv").upsert({
      community_id: order.community_id,
      key: "payments",
      value: payments,
    });
    if (paymentWrite.error) throw paymentWrite.error;

    await db.from("payment_orders").update({
      status: "captured",
      captured_at: new Date().toISOString(),
      razorpay_payment_id: paymentId,
    }).eq("id", order.id);
    await db.from("payment_events").update({
      status: "processed",
      processed_at: new Date().toISOString(),
    }).eq("event_id", eventId);
    return new Response("ok", { status: 200 });
  } catch (error) {
    const code = error instanceof Error ? error.message.slice(0, 120) : "processing_failed";
    await db.from("payment_events").update({
      status: "failed",
      error_code: code,
      processed_at: new Date().toISOString(),
    }).eq("event_id", eventId);
    console.error("razorpay-webhook-failed", code);
    return new Response("Processing failed", { status: 500 });
  }
});

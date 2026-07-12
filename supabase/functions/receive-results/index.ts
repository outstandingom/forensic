/**
 * receive-results — Supabase Edge Function
 *
 * Called by the forensic engine's --callback-url at the end of a GitHub
 * Actions workflow run.  Verifies the shared secret, then writes the
 * finished report back to the forensic_reports table.
 *
 * Request (POST application/json):
 *   {
 *     report_id: string,           // forensic_reports row UUID
 *     report:    object | null,    // full engine output (null on error)
 *     error?:    string            // set when engine failed
 *   }
 *
 * Auth:
 *   x-callback-secret header must match CALLBACK_SECRET env var.
 *
 * Required env vars:
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 *   CALLBACK_SECRET               — shared with GitHub Actions secrets
 */

import { serve }        from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// ─── helpers ──────────────────────────────────────────────────────────────────

function env(key: string): string {
  const val = Deno.env.get(key);
  if (!val) throw new Error(`Missing env var: ${key}`);
  return val;
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ─── main ─────────────────────────────────────────────────────────────────────

serve(async (req: Request) => {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  // ── Auth: shared-secret header ───────────────────────────────────────────
  const incomingSecret = req.headers.get("x-callback-secret") ?? "";
  const expectedSecret = env("CALLBACK_SECRET");

  // Constant-time comparison to avoid timing attacks
  const encoder = new TextEncoder();
  const a = encoder.encode(incomingSecret);
  const b = encoder.encode(expectedSecret);
  let mismatch = a.length !== b.length ? 1 : 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    mismatch |= a[i] ^ b[i];
  }
  if (mismatch) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }

  // ── Parse body ───────────────────────────────────────────────────────────
  let body: { report_id?: string; report?: Record<string, unknown> | null; error?: string };
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400);
  }

  const { report_id, report, error: engineError } = body;

  if (!report_id) {
    return jsonResponse({ error: "'report_id' is required" }, 400);
  }

  // ── Supabase client ──────────────────────────────────────────────────────
  const supabase = createClient(
    env("SUPABASE_URL"),
    env("SUPABASE_SERVICE_ROLE_KEY"),
  );

  // ── Build update payload ─────────────────────────────────────────────────
  const now = new Date().toISOString();

  if (engineError || !report) {
    // Engine reported a failure
    const { error: dbErr } = await supabase
      .from("forensic_reports")
      .update({
        status:        "failed",
        error_message: engineError ?? "Unknown engine error",
        completed_at:  now,
      })
      .eq("id", report_id);

    if (dbErr) {
      console.error("DB update (failed) error:", dbErr);
      return jsonResponse({ error: "DB update failed", detail: dbErr.message }, 500);
    }
    return jsonResponse({ ok: true, report_id, status: "failed" });
  }

  // ── Extract top-level fields from the risk assessment ───────────────────
  const risk      = (report.risk_assessment ?? {}) as Record<string, unknown>;
  const riskScore = typeof risk.risk_score === "number" ? risk.risk_score : null;
  const riskLevel = typeof risk.risk_level === "string" ? risk.risk_level : null;
  const summary   = typeof risk.explanation_summary === "string"
    ? risk.explanation_summary
    : null;
  const flags     = Array.isArray(risk.flags) ? risk.flags : [];

  // file_type from the engine output (overrides what was set at insert time)
  const engineFileType = typeof report.file_type === "string" ? report.file_type : null;

  const { error: dbErr } = await supabase
    .from("forensic_reports")
    .update({
      status:              "complete",
      file_type:           engineFileType,
      risk_score:          riskScore,
      risk_level:          riskLevel,
      explanation_summary: summary,
      flags:               flags,
      full_report:         report,
      completed_at:        now,
    })
    .eq("id", report_id);

  if (dbErr) {
    console.error("DB update (complete) error:", dbErr);
    return jsonResponse({ error: "DB update failed", detail: dbErr.message }, 500);
  }

  // ── Optional: send a Realtime broadcast so clients update live ───────────
  // (requires Realtime enabled for the table — enable in Supabase Dashboard)
  await supabase
    .channel("forensic-scans")
    .send({
      type:    "broadcast",
      event:   "scan_complete",
      payload: { report_id, risk_level: riskLevel, risk_score: riskScore },
    })
    .then(() => {/* ignore errors — realtime is optional */})
    .catch(() => {/* ignore */});

  return jsonResponse({ ok: true, report_id, status: "complete", risk_score: riskScore });
});

// AI Security Analyst — Supabase Edge Function
// Answers one question using ONLY the caller's own evidence, recon, assets,
// vulnerabilities and attack_events records, plus the system prompt below.
// Provider, first key found wins: GROQ_API_KEY (free, open models such as
// Llama), GEMINI_API_KEY (free tier), then ANTHROPIC_API_KEY (Claude).
// Keys stay server-side as Supabase secrets and never reach the browser.

import { createClient } from "jsr:@supabase/supabase-js@2";

const DEFAULT_SYSTEM_PROMPT = `You are the AI Security Analyst for an authorized, instructor-approved penetration-testing lab assessment. The client is the fictional CyberDome Corporation and all testing is confined to an approved lab network. You assist a student analyst who has already collected the evidence.

Rules you must follow:
- Use ONLY the records given to you in the user message (the student's evidence, recon, assets, vulnerabilities and attack_events). Do not rely on outside knowledge of this specific environment, and never invent hosts, accounts, findings, credentials or events that are not in the records.
- General security knowledge is fine (what a CVE or an ATT&CK technique means, standard remediation practice), but every statement about THIS assessment must trace to a provided record.
- Cite the Evidence IDs (for example EV-003) you relied on, inline, next to the claims they support.
- Keep fact separate from inference. Where the records do not support a conclusion, write "Insufficient evidence" instead of guessing.
- You do not run scans, exploit anything, or produce attack tooling or step-by-step intrusion instructions. You summarize, prioritize, explain, map findings to frameworks, and recommend next documentation or investigation steps within the authorized scope.
- Be concise, specific and plain-spoken.`;

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, x-client-info, apikey, content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

const TABLES: Record<string, string> = {
  evidence: "evidence_id, datetime, source, target_asset, observation, interpretation, confidence",
  recon: "evidence_id, item, category, detail, analyst_note",
  assets: "evidence_id, hostname, ip_address, port, protocol, state, service, version, risk_note, needs_investigation",
  vulnerabilities: "vuln_id, evidence_id, title, severity, cvss_score, cve_id, affected_asset, status, description, impact, remediation",
  attack_events: "evidence_id, event_time, observed_event, student_interpretation, basis, needs_more_evidence, target_asset, technique, mitre_attack_id, tool, outcome",
};

// Free-tier Gemini models, tried in order until one is available to the key.
const GEMINI_MODELS = ["gemini-2.5-flash", "gemini-flash-latest", "gemini-2.5-flash-lite", "gemini-flash-lite-latest", "gemini-2.0-flash"];

type Result = { answer?: string; model?: string; error?: string; status?: number };

async function askGemini(key: string, system: string, user: string): Promise<Result> {
  const override = Deno.env.get("ANALYST_MODEL");
  const models = override && override.startsWith("gemini") ? [override, ...GEMINI_MODELS] : GEMINI_MODELS;
  let lastErr = "";
  for (const model of models) {
    const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
      method: "POST",
      headers: { "x-goog-api-key": key, "content-type": "application/json" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: "user", parts: [{ text: user }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 8192 },
      }),
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.ok) {
      const cand = data?.candidates?.[0];
      const answer = (cand?.content?.parts || [])
        .filter((p: { text?: string; thought?: boolean }) => p.text && !p.thought)
        .map((p: { text: string }) => p.text).join("\n").trim();
      if (answer) return { answer, model };
      lastErr = `empty answer (finish reason: ${cand?.finishReason || data?.promptFeedback?.blockReason || "unknown"})`;
      continue;
    }
    const msg: string = data?.error?.message || `HTTP ${resp.status}`;
    lastErr = `${model}: ${msg}`;
    // Model not available to this key → try the next one.
    if (resp.status === 404 || /not found|not supported|is not available|limit: 0/i.test(msg)) continue;
    if (resp.status === 429) return { error: `Gemini free-tier rate limit reached (${msg}). Wait a minute and ask again.`, status: 429 };
    if (resp.status === 400 && /api key/i.test(msg)) return { error: "Gemini rejected the API key. Re-copy it from aistudio.google.com and update the GEMINI_API_KEY secret.", status: 502 };
    return { error: `Gemini API error — ${lastErr}`, status: 502 };
  }
  return { error: `No Gemini model was available to this key. Last error — ${lastErr}`, status: 502 };
}

// Free Groq models (OpenAI-compatible API), tried in order.
const GROQ_MODELS = ["llama-3.3-70b-versatile", "openai/gpt-oss-120b", "openai/gpt-oss-20b", "llama-3.1-8b-instant"];

async function askGroq(key: string, system: string, user: string): Promise<Result> {
  const override = Deno.env.get("ANALYST_MODEL");
  const models = override && !override.startsWith("gemini") && !override.startsWith("claude") ? [override, ...GROQ_MODELS] : GROQ_MODELS;
  let lastErr = "";
  for (const model of models) {
    const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { "authorization": `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify({
        model, temperature: 0.2, max_tokens: 4096,
        messages: [{ role: "system", content: system }, { role: "user", content: user }],
        // Reasoning models spend tokens thinking before answering; keep that small and hidden.
        ...(model.startsWith("openai/gpt-oss") ? { reasoning_effort: "low", include_reasoning: false } : {}),
      }),
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.ok) {
      const choice = data?.choices?.[0];
      const answer = String(choice?.message?.content || "").trim();
      console.log(`groq model=${model} finish=${choice?.finish_reason} chars=${answer.length}`);
      // A cut-off answer is worse than none: try the next model instead.
      if (answer && choice?.finish_reason !== "length") return { answer, model };
      lastErr = `${model}: ${answer ? "answer was cut off" : "empty answer"} (finish reason: ${choice?.finish_reason || "unknown"})`;
      continue;
    }
    console.log(`groq model=${model} status=${resp.status} error=${data?.error?.message || ""}`);
    const msg: string = data?.error?.message || `HTTP ${resp.status}`;
    lastErr = `${model}: ${msg}`;
    if (resp.status === 401) {
      const hint = key.startsWith("gsk_") ? `starts with gsk_, ${key.length} characters` : `does NOT start with gsk_ (starts with "${key.slice(0, 4)}"), ${key.length} characters`;
      return { error: `Groq rejected the API key (the saved key ${hint}; a Groq key starts with gsk_ and is about 56 characters). Create a new key at console.groq.com/keys and save it again as the GROQ_API_KEY secret.`, status: 502 };
    }
    // Model retired, not available, or request too big for its free limit → try the next one.
    if (resp.status === 404 || resp.status === 413 || /decommissioned|not found|does not exist|too large|tokens per minute|reasoning|not supported/i.test(msg)) continue;
    if (resp.status === 429) return { error: `Groq free-tier rate limit reached (${msg}). Wait a minute and ask again.`, status: 429 };
    return { error: `Groq API error — ${lastErr}`, status: 502 };
  }
  return { error: `No Groq model accepted the request. Last error — ${lastErr}`, status: 502 };
}

async function askClaude(key: string, system: string, user: string): Promise<Result> {
  const model = Deno.env.get("ANALYST_MODEL") || "claude-3-5-sonnet-latest";
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model, max_tokens: 1500, system, messages: [{ role: "user", content: user }] }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) return { error: `Model API error: ${data?.error?.message || `HTTP ${resp.status}`}. Check ANALYST_MODEL and ANTHROPIC_API_KEY.`, status: 502 };
  const answer = Array.isArray(data.content)
    ? data.content.filter((b: { type?: string }) => b.type === "text").map((b: { text?: string }) => b.text || "").join("\n").trim()
    : "";
  return { answer, model };
}

Deno.serve(async (req) => {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { ...CORS, "content-type": "application/json" } });

  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);

  try {
    const auth = req.headers.get("Authorization") || "";
    if (!auth.startsWith("Bearer ")) return json({ error: "Sign in required." }, 401);

    // Tolerate stray spaces, line breaks or quotes pasted around a key.
    const clean = (v?: string) => (v || "").trim().replace(/^["'`]+|["'`]+$/g, "").trim() || undefined;
    const groqKey = clean(Deno.env.get("GROQ_API_KEY"));
    const geminiKey = clean(Deno.env.get("GEMINI_API_KEY"));
    const claudeKey = clean(Deno.env.get("ANTHROPIC_API_KEY"));
    if (!groqKey && !geminiKey && !claudeKey) {
      return json({ error: "No AI key is set. Add GROQ_API_KEY (free, from console.groq.com/keys) in Supabase → Edge Functions → Secrets." }, 500);
    }
    const systemPrompt = Deno.env.get("ANALYST_SYSTEM_PROMPT") || DEFAULT_SYSTEM_PROMPT;

    const payload = await req.json().catch(() => ({}));
    const question = String(payload?.question || "").trim();
    if (!question) return json({ error: "No question provided." }, 400);
    if (question.length > 4000) return json({ error: "Question is too long (4000 characters max)." }, 400);

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: auth } } },
    );

    const records: Record<string, unknown[]> = {};
    const evidenceIds = new Set<string>();
    for (const [table, cols] of Object.entries(TABLES)) {
      const { data, error } = await supabase.from(table).select(cols).limit(500);
      if (error) return json({ error: `Could not read ${table}: ${error.message}. Is the latest schema applied?` }, 500);
      records[table] = data ?? [];
      for (const row of (data ?? []) as Array<Record<string, unknown>>) {
        if (typeof row.evidence_id === "string") evidenceIds.add(row.evidence_id);
      }
    }

    const total = Object.values(records).reduce((n, rows) => n + rows.length, 0);
    if (total === 0) {
      return json({ answer: "There are no records yet in evidence, recon, assets, vulnerabilities or attack_events, so there is nothing to analyze. Log some evidence first.", evidence_ids: [], model: "none" });
    }

    const userContent =
      `QUESTION:\n${question}\n\n` +
      `These are the only records available. Answer from them alone and cite Evidence IDs.\n\n` +
      "```json\n" + JSON.stringify(records).slice(0, groqKey ? 24000 : 180000) + "\n```";

    const r = groqKey
      ? await askGroq(groqKey, systemPrompt, userContent)
      : geminiKey
        ? await askGemini(geminiKey, systemPrompt, userContent)
        : await askClaude(claudeKey!, systemPrompt, userContent);
    if (r.error) return json({ error: r.error }, r.status || 502);

    // Some models write IDs with Unicode hyphens (EV‑004); normalize so citations are detected.
    const answer = (r.answer || "").replace(/\b(EV|VULN|CVE)[\u2010-\u2015\u2212]/g, "$1-").replace(/(CVE-\d{4})[\u2010-\u2015\u2212]/g, "$1-");
    const cited = new Set((answer.match(/EV-\d+/gi) || []).map((s) => s.toUpperCase()));
    const referenced = [...cited].filter((id) => evidenceIds.has(id)).sort(
      (a, b) => a.localeCompare(b, undefined, { numeric: true }),
    );

    return json({ answer, evidence_ids: referenced, model: r.model });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});

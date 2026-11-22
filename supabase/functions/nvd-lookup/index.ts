// nvd-lookup — Supabase Edge Function (deployed by assistant)
// Takes CVE IDs and returns the official CVSS v3 base score, vector and
// English description from NIST NVD, caching results in cve_cache. A missing
// value is marked 'Not retrieved' and never fabricated.

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, x-client-info, apikey, content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

type CveResult = {
  status: "Retrieved" | "Not retrieved";
  cvss_v3_score: number | null;
  cvss_v3_vector: string | null;
  cvss_version: string | null;
  description: string | null;
  source: string;
  retrieved_at: string;
  reason?: string;
};
type CacheRow = {
  cve_id: string;
  cvss_v31_score: number | null;
  cvss_v31_vector: string | null;
  description: string | null;
  status: string;
  source: string;
  retrieved_at: string;
  cvss_version?: string | null;
};

function readNvd(body: any): { score: number; vector: string; version: string; description: string | null } | null {
  const vuln = body?.vulnerabilities?.[0]?.cve;
  if (!vuln) return null;
  const metrics = vuln.metrics || {};
  const pick = (arr: any[]): any => Array.isArray(arr) && arr.length ? arr[0] : null;
  const m31 = pick(metrics.cvssMetricV31);
  const m30 = pick(metrics.cvssMetricV30);
  const chosen = m31 || m30;
  const data = chosen?.cvssData;
  if (!data || typeof data.baseScore !== "number" || !data.vectorString) return null;
  let description: string | null = null;
  const descs = Array.isArray(vuln.descriptions) ? vuln.descriptions : [];
  const en = descs.find((d: any) => d.lang === "en") || descs[0];
  if (en && typeof en.value === "string") description = en.value.trim() || null;
  return { score: Math.round(data.baseScore * 10) / 10, vector: String(data.vectorString), version: String(data.version || (m31 ? "3.1" : "3.0")), description };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function enrich(
  cveIds: string[],
  deps: {
    cacheGet: (id: string) => Promise<CacheRow | null>;
    cachePut: (row: CacheRow) => Promise<void>;
    fetchCve: (id: string) => Promise<{ ok: boolean; status: number; body?: any; error?: string }>;
    force?: boolean;
    delayMs?: number;
  },
): Promise<{ results: Record<string, CveResult>; fetched: number; cached: number }> {
  const results: Record<string, CveResult> = {};
  const seen = new Set<string>();
  const ids = cveIds.map((s) => String(s || "").trim().toUpperCase()).filter((s) => /^CVE-\d{4}-\d{4,}$/.test(s)).filter((s) => (seen.has(s) ? false : (seen.add(s), true)));
  let fetched = 0, cached = 0;
  const nowIso = () => new Date().toISOString();
  for (const id of ids) {
    if (!deps.force) {
      let row: CacheRow | null = null;
      try { row = await deps.cacheGet(id); } catch { row = null; }
      if (row && row.status === "Retrieved") {
        cached++;
        results[id] = { status: "Retrieved", cvss_v3_score: row.cvss_v31_score, cvss_v3_vector: row.cvss_v31_vector, cvss_version: row.cvss_version ?? null, description: row.description, source: row.source || "NVD (cached)", retrieved_at: row.retrieved_at };
        continue;
      }
    }
    if (fetched > 0 && deps.delayMs) await sleep(deps.delayMs);
    fetched++;
    let res: CveResult;
    try {
      const r = await deps.fetchCve(id);
      if (!r.ok) { const why = r.error ? r.error : "NVD returned HTTP " + r.status; res = notRetrieved(nowIso(), why); }
      else {
        const parsed = readNvd(r.body);
        if (!parsed) res = notRetrieved(nowIso(), "NVD has no record or no CVSS v3 metric for this CVE");
        else res = { status: "Retrieved", cvss_v3_score: parsed.score, cvss_v3_vector: parsed.vector, cvss_version: parsed.version, description: parsed.description, source: "NVD", retrieved_at: nowIso() };
      }
    } catch (e) { res = notRetrieved(nowIso(), String((e as Error).message || e)); }
    results[id] = res;
    try {
      await deps.cachePut({ cve_id: id, cvss_v31_score: res.cvss_v3_score, cvss_v31_vector: res.cvss_v3_vector, description: res.description, status: res.status, source: res.source, retrieved_at: res.retrieved_at, cvss_version: res.cvss_version });
    } catch { /* best-effort */ }
  }
  return { results, fetched, cached };
}
function notRetrieved(at: string, reason: string): CveResult {
  return { status: "Not retrieved", cvss_v3_score: null, cvss_v3_vector: null, cvss_version: null, description: null, source: "NVD", retrieved_at: at, reason };
}

Deno.serve(async (req: Request): Promise<Response> => {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { ...CORS, "content-type": "application/json" } });
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);

  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return json({ error: "Sign in required." }, 401);

  let payload: any;
  try { payload = await req.json(); } catch { return json({ error: "Request body must be JSON." }, 400); }
  const cveIds: string[] = Array.isArray(payload?.cve_ids) ? payload.cve_ids : [];
  if (!cveIds.length) return json({ error: "Provide cve_ids: an array of CVE IDs." }, 400);
  if (cveIds.length > 100) return json({ error: "Too many CVEs in one request (100 max)." }, 413);

  const base = Deno.env.get("NVD_API_BASE") || "https://services.nvd.nist.gov/rest/json/cves/2.0";
  const apiKey = Deno.env.get("NVD_API_KEY") || "";

  let sb: any = null;
  try {
    const { createClient } = await import("jsr:@supabase/supabase-js@2");
    sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, { global: { headers: { Authorization: auth } } });
  } catch (e) {
    return json({ error: "Could not initialize the database client: " + String((e as Error).message || e) }, 500);
  }

  const cacheGet = async (id: string): Promise<CacheRow | null> => {
    const { data, error } = await sb.from("cve_cache").select("*").eq("cve_id", id).maybeSingle();
    if (error) return null;
    return (data as CacheRow) || null;
  };
  const cachePut = async (row: CacheRow): Promise<void> => { await sb.from("cve_cache").upsert(row, { onConflict: "cve_id" }); };
  const fetchCve = async (id: string) => {
    try {
      const headers: Record<string, string> = { "accept": "application/json" };
      if (apiKey) headers["apiKey"] = apiKey;
      const resp = await fetch(base + "?cveId=" + encodeURIComponent(id), { headers });
      if (!resp.ok) { try { await resp.body?.cancel(); } catch {} return { ok: false as const, status: resp.status, body: null }; }
      const body = await resp.json();
      return { ok: true as const, status: 200, body };
    } catch (e) { return { ok: false as const, status: 0, error: String((e as Error).message || e) }; }
  };

  try {
    const out = await enrich(cveIds, { cacheGet, cachePut, fetchCve, force: !!payload?.force, delayMs: apiKey ? 350 : 800 });
    return json(out);
  } catch (e) {
    return json({ error: String((e as Error).message || e) }, 500);
  }
});

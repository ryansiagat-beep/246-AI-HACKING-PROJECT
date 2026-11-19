// =====================================================================
// parse-scan — Supabase Edge Function
// File path in your project: supabase/functions/parse-scan/index.ts
//
// What it does
//   Takes the TEXT of one vulnerability-scanner or web-assessment report
//   and returns the findings it contains as plain records, plus a list of
//   any records/lines it could not parse. It does NOT touch the database
//   and it does NOT scan anything — it only reads a report you already have.
//
//   Supported formats (auto-detected, or forced with "format"):
//     - nessus   Tenable Nessus .nessus XML
//     - openvas  Greenbone / OpenVAS XML report
//     - csv      generic CSV (you map the columns in the app)
//     - nikto    Nikto output: -Format csv, -Format json, or plain text
//     - zap      OWASP ZAP report: XML or JSON
//     - nmap     Nmap XML (-oX) or normal text output (-oN / terminal).
//                Only with "target": "assets" (Scan & Enumeration); it
//                returns host/port records instead of findings.
//
// Why a function (and not the browser)
//   The assignment asks for report parsing to happen in a backend function.
//   Keeping it here means one tested parser, the same for every teammate,
//   and the browser only ever handles already-structured records.
//
// Request  (POST, signed-in teammate):
//   { "format": "auto", "filename": "scan.nessus", "text": "<...>",
//     "columnMap": { "title": "Name", "cvss_score": "CVSS", ... } }  // csv only
//
// Response:
//   { "detected_format": "nessus",
//     "record_count": 12,
//     "records": [ { record_index, title, host, port, protocol,
//                    cvss_score, cvss_vector, cve_ids, severity_raw,
//                    synopsis, description, solution, finding_type,
//                    owasp_category, url, source_ref } , ... ],
//     "errors":  [ { record_index, line, message }, ... ] }
//
// Deploy:   supabase functions deploy parse-scan
// =====================================================================

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, x-client-info, apikey, content-type",
  "access-control-allow-methods": "POST, OPTIONS",
};

// ---------------------------------------------------------------------
// Shared record shape. Every parser fills what it can and leaves the
// rest null/empty; nothing is invented.
// ---------------------------------------------------------------------
type Finding = {
  record_index: number;
  title: string;
  host: string | null;
  port: number | null;
  protocol: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cve_ids: string[];
  severity_raw: string | null; // mapped to our 5 bands; used only when there is no CVSS
  synopsis: string | null;
  description: string | null;
  solution: string | null;
  finding_type: string | null;
  owasp_category: string | null;
  url: string | null;
  source_ref: string | null; // scanner's own id: Nessus pluginID, NVT oid, ZAP pluginid
};
type ParseError = { record_index: number | null; line: number | null; message: string };

const SEVS = ["Critical", "High", "Medium", "Low", "Informational"];

function blankFinding(i: number): Finding {
  return {
    record_index: i, title: "", host: null, port: null, protocol: null,
    cvss_score: null, cvss_vector: null, cve_ids: [], severity_raw: null,
    synopsis: null, description: null, solution: null, finding_type: null,
    owasp_category: null, url: null, source_ref: null,
  };
}
function clampSev(s: string | null | undefined): string | null {
  if (!s) return null;
  const t = String(s).trim();
  const hit = SEVS.find((x) => x.toLowerCase() === t.toLowerCase());
  return hit || null;
}
function num(v: unknown): number | null {
  if (v == null || v === "") return null;
  const n = Number(String(v).trim());
  return isNaN(n) || n < 0 || n > 10 ? null : Math.round(n * 10) / 10;
}
function portNum(v: unknown): number | null {
  if (v == null || v === "") return null;
  const n = parseInt(String(v).trim(), 10);
  return isNaN(n) || n < 1 || n > 65535 ? null : n;
}
function cvesFrom(text: string): string[] {
  const out: string[] = [];
  const re = /CVE-\d{4}-\d{4,}/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const id = m[0].toUpperCase();
    if (out.indexOf(id) === -1) out.push(id);
  }
  return out;
}
function cleanText(s: string | null): string | null {
  if (s == null) return null;
  const t = s.replace(/\r\n/g, "\n").replace(/[ \t]+\n/g, "\n").trim();
  return t.length ? t : null;
}

// ---------------------------------------------------------------------
// Tiny, dependency-free XML reader. Good enough for the machine-written
// XML that scanners emit; it keeps a stack and records text + children.
// It deliberately throws with a character offset when the tags don't
// balance, so the caller can report where a report went wrong.
// ---------------------------------------------------------------------
type XmlNode = { tag: string; attrs: Record<string, string>; children: XmlNode[]; text: string };

function decodeEntities(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body) => {
    if (body[0] === "#") {
      const code = body[1] === "x" || body[1] === "X"
        ? parseInt(body.slice(2), 16)
        : parseInt(body.slice(1), 10);
      return isNaN(code) ? whole : String.fromCodePoint(code);
    }
    const named: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'", nbsp: " " };
    return body in named ? named[body] : whole;
  });
}
function offsetToLine(src: string, off: number): number {
  let line = 1;
  for (let i = 0; i < off && i < src.length; i++) if (src[i] === "\n") line++;
  return line;
}
function parseXml(src: string): XmlNode {
  // Drop declaration, comments, DOCTYPE and processing instructions.
  let s = src.replace(/<\?[\s\S]*?\?>/g, "").replace(/<!--[\s\S]*?-->/g, "").replace(/<!DOCTYPE[\s\S]*?>/gi, "");
  const root: XmlNode = { tag: "#root", attrs: {}, children: [], text: "" };
  const stack: XmlNode[] = [root];
  const tagRe = /<(\/?)([A-Za-z_][\w.:-]*)((?:\s+[^<>]*?)?)(\/?)>|<!\[CDATA\[([\s\S]*?)\]\]>/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(s))) {
    const between = s.slice(last, m.index);
    if (between) stack[stack.length - 1].text += decodeEntities(between);
    last = tagRe.lastIndex;
    if (m[5] !== undefined) { // CDATA
      stack[stack.length - 1].text += m[5];
      continue;
    }
    const closing = m[1] === "/";
    const name = m[2];
    const selfClose = m[4] === "/";
    if (closing) {
      // Pop to the matching open tag; tolerate a stray close by ignoring it.
      let depth = stack.length - 1;
      while (depth > 0 && stack[depth].tag !== name) depth--;
      if (depth === 0) continue; // no matching open — ignore
      stack.length = depth;
    } else {
      const node: XmlNode = { tag: name, attrs: parseAttrs(m[3] || ""), children: [], text: "" };
      stack[stack.length - 1].children.push(node);
      if (!selfClose) stack.push(node);
    }
  }
  const tailText = s.slice(last);
  if (tailText.trim()) root.text += decodeEntities(tailText);
  if (stack.length !== 1) {
    const unclosed = stack[stack.length - 1].tag;
    throw new Error(`XML is not well formed near line ${offsetToLine(s, last)}: <${unclosed}> was never closed.`);
  }
  if (!root.children.length) throw new Error("No XML elements were found in the report.");
  return root;
}
function parseAttrs(raw: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([A-Za-z_][\w.:-]*)\s*=\s*"([^"]*)"|([A-Za-z_][\w.:-]*)\s*=\s*'([^']*)'/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) {
    const k = m[1] || m[3];
    const v = decodeEntities(m[2] != null ? m[2] : m[4]);
    attrs[k] = v;
  }
  return attrs;
}
function findAll(node: XmlNode, tag: string): XmlNode[] {
  const out: XmlNode[] = [];
  const walk = (n: XmlNode) => {
    for (const c of n.children) {
      if (c.tag === tag) out.push(c);
      walk(c);
    }
  };
  walk(node);
  return out;
}
function kid(node: XmlNode, tag: string): XmlNode | null {
  for (const c of node.children) if (c.tag === tag) return c;
  return null;
}
function kidText(node: XmlNode, tag: string): string {
  const k = kid(node, tag);
  return k ? deepText(k).trim() : "";
}
function deepText(node: XmlNode): string {
  let t = node.text;
  for (const c of node.children) t += " " + deepText(c);
  return t;
}
function first(node: XmlNode, tags: string[]): XmlNode | null {
  for (const t of tags) { const k = kid(node, t); if (k) return k; }
  return null;
}

// ---------------------------------------------------------------------
// Nessus (.nessus XML)
// ---------------------------------------------------------------------
function parseNessus(src: string, errors: ParseError[]): Finding[] {
  const root = parseXml(src);
  const hosts = findAll(root, "ReportHost");
  if (!hosts.length) throw new Error("This does not look like a Nessus report: no <ReportHost> elements were found.");
  const findings: Finding[] = [];
  let idx = 0;
  const sevMap: Record<string, string> = { "4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Informational" };
  for (const host of hosts) {
    const hostName = host.attrs["name"] || kidText(host, "name") || null;
    for (const item of host.children.filter((c) => c.tag === "ReportItem")) {
      const i = idx++;
      try {
        const f = blankFinding(i);
        f.host = hostName;
        f.title = item.attrs["pluginName"] || kidText(item, "plugin_name") || "Unnamed Nessus plugin";
        f.port = portNum(item.attrs["port"]);
        f.protocol = (item.attrs["protocol"] || "").toLowerCase() || null;
        f.source_ref = item.attrs["pluginID"] ? "Nessus plugin " + item.attrs["pluginID"] : null;
        f.synopsis = cleanText(kidText(item, "synopsis") || null);
        f.description = cleanText(kidText(item, "description") || null);
        f.solution = cleanText(kidText(item, "solution") || null);
        const vector = kidText(item, "cvss3_vector") || kidText(item, "cvss3_base_vector") || kidText(item, "cvss_vector") || "";
        f.cvss_vector = vector || null;
        f.cvss_score = num(kidText(item, "cvss3_base_score")) ?? num(kidText(item, "cvss_base_score"));
        f.cve_ids = item.children.filter((c) => c.tag === "cve").map((c) => c.text.trim().toUpperCase()).filter((x) => /^CVE-\d{4}-\d{4,}$/.test(x));
        if (!f.cve_ids.length) f.cve_ids = cvesFrom(deepText(item));
        f.severity_raw = clampSev(sevMap[item.attrs["severity"] || ""] || null);
        f.finding_type = item.attrs["pluginFamily"] || "Host vulnerability";
        findings.push(f);
      } catch (e) {
        errors.push({ record_index: i, line: null, message: "Nessus ReportItem " + (i + 1) + ": " + String((e as Error).message || e) });
      }
    }
  }
  if (!findings.length && !errors.length) throw new Error("The Nessus report parsed, but contained no <ReportItem> findings.");
  return findings;
}

// ---------------------------------------------------------------------
// OpenVAS / Greenbone (XML)
// ---------------------------------------------------------------------
function parseOpenvas(src: string, errors: ParseError[]): Finding[] {
  const root = parseXml(src);
  const results = findAll(root, "result");
  if (!results.length) throw new Error("This does not look like an OpenVAS/Greenbone report: no <result> elements were found.");
  const findings: Finding[] = [];
  let idx = 0;
  const threatMap: Record<string, string> = {
    critical: "Critical", high: "High", medium: "Medium", low: "Low", log: "Informational", debug: "Informational", false_positive: "Informational",
  };
  for (const res of results) {
    const i = idx++;
    try {
      const f = blankFinding(i);
      const nvt = kid(res, "nvt");
      f.title = kidText(res, "name") || (nvt ? kidText(nvt, "name") : "") || "Unnamed OpenVAS result";
      // host may be plain text with child <asset>/<hostname>; take the leading token.
      const hostNode = kid(res, "host");
      if (hostNode) f.host = (hostNode.text.trim().split(/\s+/)[0] || null);
      const portRaw = kidText(res, "port"); // e.g. "443/tcp" or "general/tcp"
      const pm = /^(\d+)\/(tcp|udp|sctp)/i.exec(portRaw);
      if (pm) { f.port = portNum(pm[1]); f.protocol = pm[2].toLowerCase(); }
      else if (/\/(tcp|udp|sctp)/i.test(portRaw)) f.protocol = portRaw.split("/")[1].toLowerCase();
      f.cvss_score = num(kidText(res, "severity")); // CVSS base in GMP 7+
      if (nvt) {
        if (f.cvss_score == null) f.cvss_score = num(kidText(nvt, "cvss_base"));
        f.source_ref = nvt.attrs["oid"] ? "NVT " + nvt.attrs["oid"] : null;
        const tags = kidText(nvt, "tags");
        if (tags) {
          const map: Record<string, string> = {};
          tags.split("|").forEach((part) => { const eq = part.indexOf("="); if (eq > 0) map[part.slice(0, eq).trim()] = part.slice(eq + 1).trim(); });
          f.synopsis = cleanText(map["summary"] || null);
          f.solution = cleanText(map["solution"] || null);
          if (map["cvss_base_vector"]) f.cvss_vector = map["cvss_base_vector"];
          if (map["insight"] && !f.synopsis) f.synopsis = cleanText(map["insight"]);
        }
        // CVE refs
        const refs = findAll(nvt, "ref").filter((r) => (r.attrs["type"] || "").toLowerCase() === "cve").map((r) => (r.attrs["id"] || "").toUpperCase());
        f.cve_ids = refs.filter((x) => /^CVE-\d{4}-\d{4,}$/.test(x));
      }
      f.description = cleanText(kidText(res, "description") || null);
      if (!f.cve_ids.length) f.cve_ids = cvesFrom(deepText(res));
      f.severity_raw = clampSev(threatMap[(kidText(res, "threat") || "").toLowerCase()] || null);
      f.finding_type = "Network vulnerability";
      findings.push(f);
    } catch (e) {
      errors.push({ record_index: i, line: null, message: "OpenVAS result " + (i + 1) + ": " + String((e as Error).message || e) });
    }
  }
  if (!findings.length && !errors.length) throw new Error("The OpenVAS report parsed, but contained no <result> findings.");
  return findings;
}

// ---------------------------------------------------------------------
// OWASP ZAP (XML or JSON)
// ---------------------------------------------------------------------
function zapRiskToSev(code: string): string | null {
  const map: Record<string, string> = { "3": "High", "2": "Medium", "1": "Low", "0": "Informational" };
  return clampSev(map[String(code).trim()] || code || null);
}
function parseZapXml(src: string, errors: ParseError[]): Finding[] {
  const root = parseXml(src);
  const items = findAll(root, "alertitem");
  if (!items.length) throw new Error("This does not look like a ZAP XML report: no <alertitem> elements were found.");
  const findings: Finding[] = [];
  let idx = 0;
  // site host for each alertitem: find the enclosing <site name="...">
  const sites = findAll(root, "site");
  const uriOfSite = (node: XmlNode): string | null => {
    for (const s of sites) if (findAll(s, "alertitem").indexOf(node) !== -1) return s.attrs["name"] || null;
    return null;
  };
  for (const it of items) {
    const i = idx++;
    try {
      const f = blankFinding(i);
      f.title = kidText(it, "alert") || kidText(it, "name") || "Unnamed ZAP alert";
      f.description = cleanText(kidText(it, "desc") || null);
      f.solution = cleanText(kidText(it, "solution") || null);
      f.synopsis = cleanText(kidText(it, "otherinfo") || null);
      f.severity_raw = zapRiskToSev(kidText(it, "riskcode"));
      f.source_ref = kidText(it, "pluginid") ? "ZAP plugin " + kidText(it, "pluginid") : null;
      const cwe = kidText(it, "cweid");
      f.finding_type = cwe ? "Web app (CWE-" + cwe + ")" : "Web application";
      const inst = findAll(it, "instance")[0];
      f.url = (inst ? kidText(inst, "uri") : "") || kidText(it, "uri") || uriOfSite(it);
      if (!f.host && f.url) { try { f.host = new URL(f.url).host; } catch (_) { /* leave null */ } }
      f.cve_ids = cvesFrom(deepText(it));
      findings.push(f);
    } catch (e) {
      errors.push({ record_index: i, line: null, message: "ZAP alert " + (i + 1) + ": " + String((e as Error).message || e) });
    }
  }
  return findings;
}
function parseZapJson(obj: any, errors: ParseError[]): Finding[] {
  const findings: Finding[] = [];
  let idx = 0;
  const sites = Array.isArray(obj?.site) ? obj.site : (obj?.site ? [obj.site] : []);
  for (const site of sites) {
    const host = site?.["@name"] || site?.name || null;
    const alerts = Array.isArray(site?.alerts) ? site.alerts : [];
    for (const a of alerts) {
      const i = idx++;
      try {
        const f = blankFinding(i);
        f.title = a.alert || a.name || "Unnamed ZAP alert";
        f.description = cleanText(a.desc || null);
        f.solution = cleanText(a.solution || null);
        f.severity_raw = zapRiskToSev(a.riskcode != null ? String(a.riskcode) : a.riskdesc || "");
        f.source_ref = a.pluginid ? "ZAP plugin " + a.pluginid : null;
        f.finding_type = a.cweid ? "Web app (CWE-" + a.cweid + ")" : "Web application";
        const inst = Array.isArray(a.instances) && a.instances.length ? a.instances[0] : null;
        f.url = (inst && (inst.uri || inst.url)) || host;
        f.host = host ? (() => { try { return new URL(host).host; } catch { return host; } })() : null;
        f.cve_ids = cvesFrom(JSON.stringify(a));
        findings.push(f);
      } catch (e) {
        errors.push({ record_index: i, line: null, message: "ZAP alert " + (i + 1) + ": " + String((e as Error).message || e) });
      }
    }
  }
  if (!findings.length && !errors.length) throw new Error("The ZAP JSON report parsed, but contained no alerts.");
  return findings;
}

// ---------------------------------------------------------------------
// Nikto (CSV, JSON, or plain text)
// ---------------------------------------------------------------------
function parseNikto(src: string, errors: ParseError[]): Finding[] {
  const trimmed = src.trim();
  // JSON form (-Format json)
  if (trimmed[0] === "{" || trimmed[0] === "[") {
    try {
      const obj = JSON.parse(trimmed);
      const arr = Array.isArray(obj) ? obj : [obj];
      const findings: Finding[] = [];
      let idx = 0;
      for (const host of arr) {
        const h = host.host || host.ip || null;
        const vulns = Array.isArray(host.vulnerabilities) ? host.vulnerabilities : [];
        for (const v of vulns) {
          const f = blankFinding(idx++);
          f.host = h;
          f.port = portNum(host.port);
          f.title = v.msg || v.id || "Nikto finding";
          f.description = cleanText(v.msg || null);
          f.url = v.url || (v.uri && h ? "http://" + h + v.uri : null);
          f.source_ref = v.id ? "Nikto " + v.id : (v.OSVDB ? "OSVDB-" + v.OSVDB : null);
          f.severity_raw = "Informational";
          f.finding_type = "Web server finding";
          f.cve_ids = cvesFrom(JSON.stringify(v));
          findings.push(f);
        }
      }
      return findings;
    } catch (e) {
      errors.push({ record_index: null, line: null, message: "Nikto JSON could not be read: " + String((e as Error).message || e) });
      return [];
    }
  }
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  // CSV form: quoted columns "host","ip","port","osvdb","method","uri","result"
  const looksCsv = lines.some((l) => /^"[^"]*","[^"]*","\d+"/.test(l.trim()));
  const findings: Finding[] = [];
  let idx = 0;
  if (looksCsv) {
    lines.forEach((line, n) => {
      const t = line.trim();
      if (!t) return;
      const cols = splitCsvLine(t);
      if (cols.length < 7) { errors.push({ record_index: null, line: n + 1, message: "Nikto CSV line " + (n + 1) + ": expected 7 columns, found " + cols.length + "." }); return; }
      const f = blankFinding(idx++);
      f.host = cols[0] || cols[1] || null;
      f.port = portNum(cols[2]);
      f.source_ref = cols[3] ? "OSVDB-" + cols[3] : null;
      f.url = cols[5] && f.host ? "http://" + f.host + (f.port && f.port !== 80 ? ":" + f.port : "") + cols[5] : (cols[5] || null);
      f.title = cleanText(cols[6]) || "Nikto finding";
      f.description = cleanText(cols[6]);
      f.severity_raw = "Informational";
      f.finding_type = "Web server finding";
      f.cve_ids = cvesFrom(t);
      findings.push(f);
    });
    return findings;
  }
  // Plain text: lines beginning with "+ " are findings.
  let currentHost: string | null = null;
  let currentPort: number | null = null;
  lines.forEach((line, n) => {
    const hostM = /Target (?:IP|Host(?:name)?):\s*(\S+)/i.exec(line);
    if (hostM) currentHost = hostM[1];
    const portM = /Target Port:\s*(\d+)/i.exec(line);
    if (portM) currentPort = portNum(portM[1]);
    const m = /^\s*\+\s+(.*\S)\s*$/.exec(line);
    if (!m) return;
    const body = m[1];
    // Skip the banner/summary "+ " lines that are not findings.
    if (/^(Target|Start Time|End Time|Server:|\d+ host\(s\) tested|SSL Info)/i.test(body)) return;
    const f = blankFinding(idx++);
    f.host = currentHost;
    f.port = currentPort;
    f.title = body.length > 120 ? body.slice(0, 117) + "…" : body;
    f.description = cleanText(body);
    const osvdb = /OSVDB-(\d+)/i.exec(body);
    f.source_ref = osvdb ? "OSVDB-" + osvdb[1] : null;
    const uri = /:\s*(\/\S*)/.exec(body);
    if (uri && currentHost) f.url = "http://" + currentHost + (currentPort && currentPort !== 80 ? ":" + currentPort : "") + uri[1];
    f.severity_raw = "Informational";
    f.finding_type = "Web server finding";
    f.cve_ids = cvesFrom(body);
    findings.push(f);
  });
  if (!findings.length && !errors.length) {
    throw new Error("No Nikto findings were recognized. Nikto text findings start with '+ '. If this is CSV or JSON output, choose that format or check the file.");
  }
  return findings;
}

// ---------------------------------------------------------------------
// Generic CSV with a column map chosen in the app.
// map maps our field name -> the CSV header to read it from.
// ---------------------------------------------------------------------
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += c;
    } else {
      if (c === '"') q = true;
      else if (c === ",") { out.push(cur); cur = ""; }
      else cur += c;
    }
  }
  out.push(cur);
  return out.map((s) => s.trim());
}
function parseCsv(src: string, map: Record<string, string>, errors: ParseError[]): Finding[] {
  const rows = src.replace(/\r\n/g, "\n").split("\n").filter((l, i) => i === 0 || l.trim().length);
  if (rows.length < 2) throw new Error("The CSV has a header row but no data rows.");
  const headers = splitCsvLine(rows[0]);
  const hIndex: Record<string, number> = {};
  headers.forEach((hd, i) => { hIndex[hd.trim().toLowerCase()] = i; });
  const col = (field: string): number => {
    const header = map[field];
    if (!header) return -1;
    const i = hIndex[header.trim().toLowerCase()];
    return i == null ? -1 : i;
  };
  if (!map["title"] || col("title") === -1) {
    throw new Error("Map the 'Finding title' field to one of the CSV columns before importing. Columns found: " + headers.join(", "));
  }
  const findings: Finding[] = [];
  const get = (cells: string[], field: string): string => { const i = col(field); return i === -1 ? "" : (cells[i] ?? "").trim(); };
  for (let r = 1; r < rows.length; r++) {
    const lineNo = r + 1;
    const cells = splitCsvLine(rows[r]);
    try {
      if (cells.length < headers.length) {
        errors.push({ record_index: r - 1, line: lineNo, message: "CSV line " + lineNo + ": expected " + headers.length + " columns, found " + cells.length + "." });
        continue;
      }
      const f = blankFinding(r - 1);
      f.title = get(cells, "title") || "Untitled finding";
      f.host = get(cells, "host") || null;
      f.port = portNum(get(cells, "port"));
      f.protocol = (get(cells, "protocol") || "").toLowerCase() || null;
      f.cvss_score = num(get(cells, "cvss_score"));
      f.cvss_vector = get(cells, "cvss_vector") || null;
      f.cve_ids = cvesFrom(get(cells, "cve_ids") || get(cells, "title") + " " + get(cells, "description"));
      f.severity_raw = clampSev(get(cells, "severity_raw"));
      f.description = cleanText(get(cells, "description") || null);
      f.synopsis = cleanText(get(cells, "synopsis") || null);
      f.solution = cleanText(get(cells, "solution") || null);
      f.finding_type = get(cells, "finding_type") || null;
      f.owasp_category = get(cells, "owasp_category") || null;
      f.url = get(cells, "url") || null;
      f.source_ref = get(cells, "source_ref") || null;
      findings.push(f);
    } catch (e) {
      errors.push({ record_index: r - 1, line: lineNo, message: "CSV line " + lineNo + ": " + String((e as Error).message || e) });
    }
  }
  if (!findings.length && !errors.length) throw new Error("No data rows could be read from the CSV.");
  return findings;
}

// ---------------------------------------------------------------------
// Nmap (XML from -oX, or the normal text output from -oN / the terminal)
// Returns one record per host and port, for the Scan & Enumeration page.
// Nmap host/port output is enumeration data, not vulnerability findings,
// so these records use their own shape (NmapRecord) and are only
// returned when the caller asks for target "assets".
// ---------------------------------------------------------------------
type NmapRecord = {
  record_index: number;
  ip_address: string | null;
  hostname: string | null;
  port: number | null;
  protocol: string | null;
  state: string | null;      // open, closed, filtered, unfiltered, open|filtered, closed|filtered
  service: string | null;    // e.g. ssh, http, ssl/http
  version: string | null;    // product + version + extra info, e.g. "Apache httpd 2.4.29 (Ubuntu)"
  os_observation: string | null;
  reason: string | null;     // e.g. syn-ack
  cpe: string[];
  host_up: boolean;
};
type NmapMeta = {
  nmap_version: string | null;
  command: string | null;
  started: string | null;
  hosts_up: number | null;
  hosts_total: number | null;
  summary: string | null;
};
const NMAP_STATES = ["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"];

function blankNmap(i: number): NmapRecord {
  return {
    record_index: i, ip_address: null, hostname: null, port: null, protocol: null, state: null,
    service: null, version: null, os_observation: null, reason: null, cpe: [], host_up: true,
  };
}
function nmapState(s: string | null | undefined): string | null {
  const t = String(s || "").trim().toLowerCase();
  return NMAP_STATES.indexOf(t) === -1 ? null : t;
}
function joinVersion(parts: (string | null | undefined)[]): string | null {
  const t = parts.map((p) => (p || "").trim()).filter(Boolean).join(" ").replace(/\s+/g, " ").trim();
  return t || null;
}

function parseNmapXml(src: string, errors: ParseError[], meta: NmapMeta): NmapRecord[] {
  const root = parseXml(src);
  const run = findAll(root, "nmaprun")[0];
  if (!run) throw new Error("This does not look like Nmap XML: no <nmaprun> element was found. Save the scan with -oX.");
  meta.nmap_version = run.attrs["version"] || null;
  meta.command = run.attrs["args"] || null;
  meta.started = run.attrs["startstr"] || null;
  const fin = findAll(run, "finished")[0];
  if (fin) meta.summary = fin.attrs["summary"] || null;
  const hostsTag = findAll(run, "hosts")[0];
  if (hostsTag) {
    meta.hosts_up = hostsTag.attrs["up"] != null ? parseInt(hostsTag.attrs["up"], 10) : null;
    meta.hosts_total = hostsTag.attrs["total"] != null ? parseInt(hostsTag.attrs["total"], 10) : null;
  }

  const out: NmapRecord[] = [];
  let idx = 0;
  const hosts = run.children.filter((c) => c.tag === "host");
  hosts.forEach((host, hi) => {
    try {
      const status = kid(host, "status");
      const up = !status || (status.attrs["state"] || "up") === "up";
      const addrs = host.children.filter((c) => c.tag === "address");
      const ip = (addrs.find((a) => a.attrs["addrtype"] === "ipv4") || addrs.find((a) => a.attrs["addrtype"] === "ipv6"))?.attrs["addr"] || null;
      const hnNodes = findAll(host, "hostname");
      const hostname = (hnNodes.find((n) => n.attrs["type"] === "user") || hnNodes[0])?.attrs["name"] || null;
      // OS: best osmatch from -O, else the ostype nmap guessed from a service banner.
      const osm = findAll(host, "osmatch").sort((a, b) => (parseInt(b.attrs["accuracy"] || "0", 10) - parseInt(a.attrs["accuracy"] || "0", 10)))[0];
      const svcOsList = findAll(host, "service").map((s) => s.attrs["ostype"]).filter((x, i, a) => x && a.indexOf(x) === i);
      const svcOs = svcOsList.length ? svcOsList.join(", ") : null;
      const os = osm ? osm.attrs["name"] + (osm.attrs["accuracy"] ? " (" + osm.attrs["accuracy"] + "% match)" : "") : (svcOs ? svcOs + " (from service banner)" : null);

      const ports = findAll(host, "port");
      if (!ports.length) {
        const r = blankNmap(idx++);
        r.ip_address = ip; r.hostname = hostname; r.os_observation = os; r.host_up = up;
        if (!ip && !hostname) { errors.push({ record_index: hi, line: null, message: "Nmap host " + (hi + 1) + ": no address or hostname, skipped." }); idx--; return; }
        out.push(r);
        return;
      }
      for (const p of ports) {
        const r = blankNmap(idx++);
        r.ip_address = ip; r.hostname = hostname; r.os_observation = os; r.host_up = up;
        r.port = portNum(p.attrs["portid"]);
        r.protocol = (p.attrs["protocol"] || "").toLowerCase() || null;
        const st = kid(p, "state");
        r.state = nmapState(st?.attrs["state"]);
        r.reason = st?.attrs["reason"] || null;
        const svc = kid(p, "service");
        if (svc) {
          const tunnel = svc.attrs["tunnel"] ? svc.attrs["tunnel"] + "/" : "";
          r.service = svc.attrs["name"] ? tunnel + svc.attrs["name"] : null;
          r.version = joinVersion([svc.attrs["product"], svc.attrs["version"], svc.attrs["extrainfo"] ? "(" + svc.attrs["extrainfo"] + ")" : null]);
          r.cpe = svc.children.filter((c) => c.tag === "cpe").map((c) => c.text.trim()).filter(Boolean);
        }
        if (r.port == null) { errors.push({ record_index: r.record_index, line: null, message: "Nmap host " + (ip || hostname) + ": a <port> had no valid portid, skipped." }); continue; }
        out.push(r);
      }
    } catch (e) {
      errors.push({ record_index: hi, line: null, message: "Nmap host " + (hi + 1) + ": " + String((e as Error).message || e) });
    }
  });
  if (!out.length && !errors.length) throw new Error("The Nmap XML parsed, but no hosts were reported. Check that the scan found live hosts.");
  return out;
}

function parseNmapText(src: string, errors: ParseError[], meta: NmapMeta): NmapRecord[] {
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  const out: NmapRecord[] = [];
  let idx = 0;
  let curIp: string | null = null, curName: string | null = null;
  let hostRecords: NmapRecord[] = [];
  let hostOs: string | null = null;
  let sawHost = false;
  let inPortTable = false;

  const closeHost = () => {
    if (!sawHost) return;
    if (!hostRecords.length) {
      const r = blankNmap(idx++);
      r.ip_address = curIp; r.hostname = curName;
      hostRecords.push(r);
    }
    hostRecords.forEach((r) => { if (hostOs && !r.os_observation) r.os_observation = hostOs; });
    out.push(...hostRecords);
    hostRecords = []; hostOs = null; sawHost = false; inPortTable = false;
  };

  lines.forEach((raw, n) => {
    const line = raw.replace(/\s+$/, "");
    let m: RegExpExecArray | null;
    if ((m = /^#?\s*Nmap ([\d.]+\S*) scan initiated (.+?) as:\s*(.+)$/.exec(line))) {
      meta.nmap_version = m[1]; meta.started = m[2]; meta.command = m[3]; return;
    }
    if ((m = /^Starting Nmap ([\d.]+\S*)[^)]*\)\s*at\s+(.+)$/.exec(line))) {
      meta.nmap_version = meta.nmap_version || m[1]; meta.started = meta.started || m[2]; return;
    }
    if ((m = /^#?\s*Nmap done(?: at [^;]+;)?:?\s*(\d+) IP address(?:es)? \((\d+) hosts? up\)(.*)$/.exec(line))) {
      meta.hosts_total = parseInt(m[1], 10); meta.hosts_up = parseInt(m[2], 10);
      meta.summary = line.replace(/^#\s*/, "");
      return;
    }
    if ((m = /^Nmap scan report for (.+)$/.exec(line))) {
      closeHost();
      sawHost = true;
      const target = m[1].trim();
      const pm = /^(\S+)\s+\(([^)]+)\)$/.exec(target);
      if (pm) { curName = pm[1]; curIp = pm[2]; }
      else if (/^[\d.]+$|^[0-9a-f:]+$/i.test(target)) { curIp = target; curName = null; }
      else { curName = target; curIp = null; }
      return;
    }
    if (!sawHost) return;
    if (/^PORT\s+STATE\s+SERVICE/.test(line)) { inPortTable = true; return; }
    if ((m = /^(\d+)\/(tcp|udp|sctp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/.exec(line))) {
      const r = blankNmap(idx++);
      r.ip_address = curIp; r.hostname = curName;
      r.port = portNum(m[1]);
      r.protocol = m[2].toLowerCase();
      r.state = nmapState(m[3]);
      r.service = m[4] || null;
      r.version = joinVersion([m[5] || null]);
      if (r.port == null || !r.state) {
        errors.push({ record_index: r.record_index, line: n + 1, message: "Line " + (n + 1) + ": could not read the port or state in \"" + line.trim() + "\"." });
        idx--; return;
      }
      hostRecords.push(r);
      return;
    }
    if ((m = /^(?:OS details|Running(?: \(JUST GUESSING\))?|Aggressive OS guesses):\s*(.+)$/.exec(line))) {
      if (!hostOs || /^OS details/.test(line)) hostOs = m[1].split(/,\s*(?=[A-Z])/)[0].trim();
      return;
    }
    if ((m = /^Service Info:.*?\bOS(?:s)?:\s*([^;]+)/.exec(line))) {
      if (!hostOs) hostOs = m[1].trim() + " (from service banner)";
      return;
    }
    if (inPortTable && line.trim() === "") inPortTable = false;
  });
  closeHost();
  if (!out.length && !errors.length) {
    throw new Error("No Nmap hosts were recognized. Upload the XML (-oX) file, or paste the normal output that includes the \"Nmap scan report for\" lines and the PORT table.");
  }
  return out;
}

function parseNmap(src: string, errors: ParseError[], meta: NmapMeta): NmapRecord[] {
  return /<nmaprun\b/.test(src.slice(0, 5000)) ? parseNmapXml(src, errors, meta) : parseNmapText(src, errors, meta);
}
function isNmap(text: string): boolean {
  const head = text.slice(0, 5000);
  return /<nmaprun\b|<!DOCTYPE nmaprun/.test(head) ||
    /^#?\s*Nmap [\d.]+\S* scan initiated|^Starting Nmap [\d.]|^Nmap scan report for /m.test(head);
}

// ---------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------
function detect(text: string, filename: string): string {
  const head = text.slice(0, 4000);
  const fn = (filename || "").toLowerCase();
  if (isNmap(text)) return "nmap";
  if (/<NessusClientData|<ReportHost\b/.test(head) || fn.endsWith(".nessus")) return "nessus";
  if (/<OWASPZAPReport|<alertitem\b/.test(head)) return "zap";
  if (/<report[\s>][\s\S]*<results\b|<result\b[\s\S]*<nvt\b|GMP|openvas|greenbone/i.test(head)) return "openvas";
  const t = text.trim();
  if (t[0] === "{" || t[0] === "[") {
    if (/"@version"|OWASP ZAP|"alerts"\s*:/.test(head)) return "zap";
    if (/"vulnerabilities"\s*:|"banner"\s*:|nikto/i.test(head)) return "nikto";
    return "zap"; // default JSON to ZAP shape; it reports clearly if wrong
  }
  if (/^\s*\+\s+Target|Nikto v|OSVDB-/im.test(head)) return "nikto";
  if (/^"[^"]*","[^"]*","\d+"/m.test(head)) return "nikto"; // nikto csv
  if (/[,;]/.test(head.split("\n")[0] || "")) return "csv";
  return "unknown";
}

const handler = async (req: Request): Promise<Response> => {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { ...CORS, "content-type": "application/json" } });
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);

  // A signed-in teammate is required, matching the rest of the app.
  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return json({ error: "Sign in required." }, 401);

  let payload: any;
  try { payload = await req.json(); } catch { return json({ error: "Request body must be JSON." }, 400); }
  const text = typeof payload?.text === "string" ? payload.text : "";
  if (!text.trim()) return json({ error: "No report text was provided." }, 400);
  if (text.length > 20_000_000) return json({ error: "That report is larger than 20 MB. Split it or import per host." }, 413);
  const filename = String(payload?.filename || "");
  let format = String(payload?.format || "auto").toLowerCase();
  if (format === "auto") format = detect(text, filename);
  // "assets" = Scan & Enumeration import (host/port rows). Default is the
  // vulnerability import, which keeps its original behavior.
  const target = String(payload?.target || "vulnerabilities").toLowerCase();

  if (target === "assets") {
    if (format !== "nmap") {
      return json({ error: "Only Nmap output can be imported on Scan & Enumeration. Upload the -oX XML file or paste the normal Nmap output. Vulnerability reports (Nessus, OpenVAS, ZAP, Nikto, CSV) go on the Vulnerabilities page.", detected_format: format }, 422);
    }
    const nErrors: ParseError[] = [];
    const meta: NmapMeta = { nmap_version: null, command: null, started: null, hosts_up: null, hosts_total: null, summary: null };
    let assets: NmapRecord[] = [];
    try { assets = parseNmap(text, nErrors, meta); }
    catch (e) { return json({ error: String((e as Error).message || e), detected_format: "nmap" }, 422); }
    return json({ detected_format: "nmap", kind: "assets", record_count: assets.length, records: assets, errors: nErrors, meta });
  }
  if (format === "nmap") {
    return json({ error: "This is Nmap output (hosts, ports and services), not a vulnerability report. Import it on the Scan & Enumeration page.", detected_format: "nmap" }, 422);
  }

  const errors: ParseError[] = [];
  let records: Finding[] = [];
  try {
    switch (format) {
      case "nessus": records = parseNessus(text, errors); break;
      case "openvas": records = parseOpenvas(text, errors); break;
      case "zap":
        if (text.trim()[0] === "{" || text.trim()[0] === "[") records = parseZapJson(JSON.parse(text), errors);
        else records = parseZapXml(text, errors);
        break;
      case "nikto": records = parseNikto(text, errors); break;
      case "csv": records = parseCsv(text, (payload?.columnMap || {}) as Record<string, string>, errors); break;
      default:
        return json({ error: "Could not tell what kind of report this is. Pick the format (Nessus, OpenVAS, CSV, Nikto or ZAP) and try again.", detected_format: "unknown" }, 422);
    }
  } catch (e) {
    return json({ error: String((e as Error).message || e), detected_format: format }, 422);
  }

  return json({ detected_format: format, record_count: records.length, records, errors });
};

// Supabase runs this file as the entry point, so the server starts there.
// When imported by a test (import.meta.main === false), no port is bound.
if (import.meta.main !== false) Deno.serve(handler);
export { handler };

// Exported for local testing (ignored by Deno.serve at runtime).
export const __test = {
  parseNessus, parseOpenvas, parseZapXml, parseZapJson, parseNikto, parseCsv, parseNmap, detect, parseXml, splitCsvLine,
};

# AI Ethical Hacking Command Center

An AI-assisted dashboard for ethical hacking assessments, built for NWIT 246 (Attackers' Tools and Techniques, Fall 2026) at Montgomery College. The client, CyberDome Corporation, is fictional. It stores and presents the evidence from an authorized lab assessment (scope: `192.168.56.0/24`) and helps an analyst see what was found, why it matters, what to investigate next and what to fix. Every finding links to an Evidence ID.

> **Authorized lab use only.** The platform only documents evidence. It never scans or attacks anything. Only assess instructor-approved targets.

**Team:** Black Ice Security. Members: Ryan Siagat (Recon Lead) · Olma (Network Assessment Lead) · Elnathan (Vulnerability Lead) · Darien (AI/Reporting Lead) · Jacob (Demo Lead)

## What's in here

| File | What it is |
|---|---|
| `index.html` | The whole web app in one self-contained page (HTML/CSS/JavaScript). Open it in a browser. |
| `schema.sql` | The Supabase (Postgres) schema with Row-Level Security. Run it once in the Supabase SQL Editor. |
| `PRD.md` | Product Requirements Document (final, updated to match what was built). |
| `supabase/functions/parse-scan/index.ts` | Edge Function: parses Nessus / OpenVAS / Nikto / ZAP / CSV reports, and Nmap output for Scan & Enumeration. |
| `supabase/functions/nvd-lookup/index.ts` | Edge Function: official CVSS/CVE details from NIST NVD (cached; reports "Not retrieved" instead of guessing a score). |
| `supabase/functions/ai-analyst/index.ts` | Edge Function: evidence-grounded AI analysis. Uses Groq (free, open models); also supports Gemini or Claude keys. |

## Modules

Executive Dashboard · Engagement · Recon · Scan & Enumeration · Vulnerabilities · Attack Evidence · AI Security Analyst · Evidence Locker · Reports.

## Demo features (read-only)

- **Presenter mode:** click **Present** (top bar). Full screen, larger text, edit buttons hidden, a 12-minute talk timer and the speaker for each section. Use the **→ / ←** arrow keys (or a slide clicker) to move through Dashboard → Engagement → Recon → Scan → Vulnerabilities → Attack Evidence → AI Analyst → Reports. Press **Esc** to exit.
- **Search / command palette:** press **Ctrl + K** (⌘K on a Mac) or click **Search**. Type a section, a VULN-ID, an EV-ID, a port or a word (e.g. `ntp`), then press **Enter**.
- **Evidence chain:** click the "N records" count in the Evidence Locker's *Cited by* column (or pick an EV-ID in search) to see every recon item, scan row, finding, AI analysis and report that cites that evidence.
- **Attack path:** dashboard diagram that chains the top-ranked open findings into a risk scenario (not an attack the team performed).
- **Network map:** dashboard diagram of the assessor and each in-scope host, with every open port colored by its worst open finding.
- **Animated numbers:** dashboard counts and the severity donut animate in (turned off automatically if the computer is set to reduce motion).
- **Boot sequence:** a short "access granted" intro the first time the app opens in a browser session (click or press any key to skip).
- **Live ticker:** the footer scrolls the open findings and latest evidence; click an item to open it. Hover to pause.
- **Testing-window countdown:** live countdown on the dashboard to the end of the authorized testing window.
- **MITRE ATT&CK coverage:** on Attack Evidence, a 14-tactic matrix lights up the tactics and techniques found in the attack events.
- **Depth and motion:** 3D raised cards that tilt toward the mouse, a moving grid floor, a cursor spotlight and animated packets on the network map. All motion turns off when the computer is set to reduce motion.

None of these features change any data.

## Setup

1. **Create a Supabase project**, then run `schema.sql` in **SQL Editor → New query**.
2. **Deploy the Edge Functions** (Supabase CLI or dashboard): `parse-scan`, `nvd-lookup`, `ai-analyst`.
3. **Set secrets** in Supabase → Edge Functions → Secrets (never in the browser or this repo):
   - `GROQ_API_KEY`: free key from console.groq.com, for the AI analyst (or `GEMINI_API_KEY` / `ANTHROPIC_API_KEY`)
   - `NVD_API_KEY`: optional, for faster CVE lookups
4. **Open `index.html`**, click **Connect Supabase**, and paste your Project URL and the anon key.
5. **Create a team login** in Supabase → Authentication → Users, then **Sign in** to edit.

## Security

- This code contains no API keys or passwords. They are stored as Supabase secrets and read only on the server.
- Row-Level Security: anyone with the anon key can read; only signed-in teammates can change data.
- The AI receives only project records, must cite Evidence IDs and must say "insufficient evidence" when data is missing; an analyst verifies every answer before it is saved.
- Never commit real secrets, passwords or sensitive evidence to this repository.

## Stack

Vanilla HTML/CSS/JS · Supabase (Postgres, Row-Level Security, Storage, Edge Functions in Deno/TypeScript) · Groq API (open models) for AI analysis · NIST NVD API for CVSS.

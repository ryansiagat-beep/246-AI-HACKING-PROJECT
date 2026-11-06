# AI Ethical Hacking Command Center

An AI-assisted ethical-hacking assessment dashboard built for **NWIT 246 — Attacker Tools and Techniques (Fall 2026)**, for the fictional client **CyberDome Corporation**. It stores and presents the evidence collected during an authorized lab assessment (scope: `192.168.56.0/24`) and helps an analyst understand what was found, why it matters, what to investigate next, and what to remediate.

> **Authorized lab use only.** This platform documents evidence; it does **not** scan or attack anything. Only assess instructor-approved targets.

## What's in here

| File | What it is |
|---|---|
| `index.html` | The whole web app — a single self-contained page (HTML/CSS/JavaScript). Open it in a browser to run it. |
| `schema.sql` | The Supabase (Postgres) database schema. Run it once in the Supabase SQL Editor. |
| `PRD.md` | Product Requirements Document. |
| `supabase/functions/parse-scan/index.ts` | Edge Function: parses Nessus / OpenVAS / Nikto / ZAP / CSV scan reports. |
| `supabase/functions/nvd-lookup/index.ts` | Edge Function: official CVSS/CVE lookup from NIST NVD (cached). |
| `supabase/functions/ai-analyst/index.ts` | Edge Function: evidence-grounded AI analysis (Claude). |

## Modules

Home / Executive Dashboard · Engagement · Recon · Scan & Enumeration · Vulnerabilities · Attack Evidence · AI Security Analyst · Evidence Locker · Reports.

## Setup

1. **Create a Supabase project**, then run `schema.sql` in **SQL Editor → New query**.
2. **Deploy the Edge Functions** (Supabase CLI or dashboard): `parse-scan`, `nvd-lookup`, `ai-analyst`.
3. **Set secrets** on the functions (Supabase → Edge Functions → Secrets) — never put these in the browser:
   - `ANTHROPIC_API_KEY` — for the AI analyst
   - `NVD_API_KEY` — optional, for faster CVE lookups
4. **Open `index.html`** in a browser, click **Connect Supabase**, and paste your Project URL + anon key.
5. **Create a team login** in Supabase → Authentication → Users, then **Sign in to edit**.

## Security

- No API keys or passwords live in this code — they are Supabase secrets, read server-side only.
- Row-Level Security: anyone with the anon key can read; only signed-in teammates can change data.
- Never commit real secrets, passwords, or sensitive evidence to this repository.

## Stack

Vanilla HTML/CSS/JS front end · Supabase (Postgres + Row-Level Security + Storage) · Supabase Edge Functions (Deno/TypeScript) · Claude (Anthropic) for AI analysis.

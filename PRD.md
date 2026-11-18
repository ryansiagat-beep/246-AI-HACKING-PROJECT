# Product Requirements Document (PRD)
## AI Ethical Hacking Command Center — CyberDome Corporation Assessment

**Course:** NWIT 246 — Attacker Tools and Techniques (Fall 2026)
**Instructor:** Professor Reza Mirabrishami
**Final due:** Monday, November 23, 2026

---

| PRD Field | Response |
|---|---|
| **Project Name** | AI Ethical Hacking Command Center |
| **Team Members / Roles** | Ryan Siagat — Recon Lead · Olma — Network Assessment Lead · Elnathan — Vulnerability Lead · Darien — AI / Reporting Lead |
| **Problem Statement** | CyberDome Corporation has expanded its network and web services and is concerned that new systems may have unnecessary services, weak configurations, or outdated software. The team needs one place to store, organize, and interpret the evidence from an authorized assessment so an analyst can see what was found, why it matters, what to investigate next, and what to remediate. |
| **Primary Users** | Ethical hacker / security analyst (daily use), Vulnerability lead (triage), Manager (executive view of risk). |
| **Project Goal** | A user can log evidence, review discovered assets and vulnerabilities, build an attack-evidence timeline, ask an evidence-grounded AI analyst questions, and produce an executive summary — all tied back to Evidence IDs. |
| **In Scope** | The instructor-approved lab network **192.168.56.0/24**; recon, scanning/enumeration, vulnerability analysis, attack-evidence analysis, AI-assisted reporting; sanitized tool output and instructor-provided evidence. |
| **Out of Scope** | Any system outside 192.168.56.0/24; public Internet targets, other students, college production systems; denial-of-service, destructive testing, persistence, credential theft, or data exfiltration; entering real secrets into AI tools. |
| **Platform Choice** | Single-page web application (HTML/CSS/JavaScript), run locally and optionally hosted on a static web host. |
| **Data Storage** | Supabase (Postgres) with Row-Level Security; private `evidence-files` storage bucket for uploads. |
| **AI Provider** | Claude (Anthropic), called from a Supabase Edge Function so the API key stays server-side. |
| **Security / Privacy Controls** | API keys never placed in the browser (held as Edge Function secrets); reading is open to the team key but all changes require a signed-in teammate (RLS); only sanitized evidence is stored; the AI receives only project records and is instructed never to invent facts. |
| **Required Modules** | Home / Executive Dashboard, Engagement, Recon, Scan & Enumeration, Vulnerabilities, Attack Evidence, AI Security Analyst, Evidence Locker, Reports — all present and linked from the main navigation. |
| **Success Criteria** | All six labs are represented; each technical module shows at least one real/supplied evidence item; AI output cites Evidence IDs and invents nothing; the platform can display a clear executive summary; the demo runs within the time limit. |
| **Known Risks / Limitations** | Free Supabase projects pause after inactivity (must be restored before a demo); scanner/PCAP evidence depends on instructor-provided lab access; the AI analyst requires an Anthropic API key configured as a secret; hosted version exposes read-only data to anyone with the link. |

---

## User Stories

1. As a **security analyst**, I want to view discovered ports so that I can understand the exposed attack surface.
2. As a **manager**, I want to see findings by severity so that I can prioritize remediation.
3. As a **vulnerability lead**, I want to import a real scanner report (Nessus / OpenVAS / Nikto / ZAP / CSV) so that findings are captured accurately without manual retyping.
4. As an **AI / reporting lead**, I want the AI analyst to answer using only our evidence and cite Evidence IDs so that every conclusion is traceable and can be verified.
5. As a **security analyst**, I want every finding to link to an Evidence ID in the Evidence Locker so that the assessment is defensible and auditable.

## Acceptance Criteria

- All required modules are accessible from the main navigation. ✔ (built)
- At least one real/supplied evidence item is visible in each technical module. *(in progress — see status)*
- AI output references evidence and does not invent unsupported facts. ✔ (system prompt + Evidence-ID citation enforced)
- The final platform can produce or display a clear executive summary. ✔ (Reports module)
- The platform is demonstrable within the presentation time limit. ✔

## Architecture (one line)

Browser SPA → Supabase (Postgres + RLS + Storage) for all records; three Supabase Edge Functions provide the backend logic — `parse-scan` (reads scanner reports), `nvd-lookup` (official CVSS from NIST NVD), and `ai-analyst` (evidence-grounded Claude analysis).

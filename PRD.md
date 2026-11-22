# Product Requirements Document (PRD): final, as implemented
## AI Ethical Hacking Command Center for the CyberDome Corporation assessment

**Course:** NWIT 246, Attackers' Tools and Techniques (Fall 2026), Montgomery College
**Instructor:** Professor Reza Mirabrishami
**Final due:** Monday, November 23, 2026 · **Version:** 1.0 (final, updated to match what was built)

---

| PRD Field | Response (final) |
|---|---|
| **Project Name** | AI Ethical Hacking Command Center |
| **Team Name** | Black Ice Security |
| **Team Members / Roles** | Ryan Siagat (Recon Lead) · Olma (Network Assessment Lead) · Elnathan (Vulnerability Lead) · Darien (AI/Reporting Lead) · Jacob (Demo Lead) |
| **Problem Statement** | CyberDome Corporation expanded its network and web services and is concerned that new systems may have unnecessary services, weak configurations or outdated software. The team needed one place to store and interpret the evidence from an authorized assessment so an analyst can see what was found, why it matters, what to investigate next and what to fix. |
| **Primary Users** | Ethical hacker / security analyst (daily use), vulnerability lead (triage and prioritization), manager (executive view of risk). |
| **Project Goal** | A user can log evidence, review discovered assets and vulnerabilities, build an attack timeline, ask an evidence-grounded AI analyst questions and verify its answers, and produce an executive summary, with everything tied back to Evidence IDs. |
| **In Scope** | Lab network **192.168.56.0/24** (pfSense firewall 192.168.56.10 and the Windows host-only adapter 192.168.56.1), testing window Sep 21 – Nov 22, 2026; recon, scanning and enumeration, vulnerability analysis, attack-evidence analysis, AI-assisted reporting; sanitized tool output. |
| **Out of Scope** | Anything outside 192.168.56.0/24; public Internet targets, other students, college production systems; denial of service, destructive testing, persistence, credential theft, exfiltration; exploitation or login attempts; real secrets in AI tools. |
| **Platform Choice** | Single-page web application (HTML/CSS/JavaScript, one `index.html`), run locally or hosted on a static web host (Netlify Drop). |
| **Data Storage** | Supabase (Postgres) with Row-Level Security; private `evidence-files` storage bucket for uploaded screenshots and reports. |
| **AI Provider** | Groq free API (open models, e.g. Llama / gpt-oss), called from the `ai-analyst` Supabase Edge Function. The function also supports Google Gemini and Anthropic Claude keys; Groq was chosen because it is free and the other APIs required payment or were unavailable to the team's accounts. |
| **Security / Privacy Controls** | AI key stored only as an Edge Function secret (never in the browser or GitHub); anyone with the anon key can read, only signed-in teammates can write (RLS); evidence sanitized before upload; the AI receives only project records, must cite Evidence IDs and must say "insufficient evidence" when data is missing; an analyst verifies every AI answer before it is saved. |
| **Required Modules** | Executive Dashboard, Engagement, Recon, Scan & Enumeration, Vulnerabilities, Attack Evidence, AI Security Analyst, Evidence Locker, Reports. All nine are built and in the main navigation. |
| **Success Criteria** | All six labs represented with real evidence; each finding traceable to an EV-ID; AI output cites evidence and its errors are caught and recorded; the Reports module shows an executive summary and technical report; the demo runs in 10–12 minutes. |
| **Known Risks / Limitations** | Free Supabase projects pause after about a week of inactivity (restore before the demo); free AI tier has per-minute rate limits; Lab 5 used a public training capture (outside scope) because no instructor PCAP was supplied; DNS/NTP reachability from the WAN was not tested; no credentialed testing. |

---

## What was built (implementation summary)

- Engagement: client, purpose, scope, exclusions, testing window, prohibited actions, rules of engagement, team roles, and a signs-of-compromise indicator table (8 indicators from Kali, Windows and the Lab 5 capture).
- Recon: 5 classified recon items (Asset, Technology, Identity, Attack-surface) with analyst notes, from `nmap -sn` and browser review.
- Scan & Enumeration: 6 services across 2 hosts with host, IP, port, protocol, state, service, version, normal-purpose risk notes and investigation flags.
- Vulnerabilities: report import (`parse-scan`: Nessus, OpenVAS, Nikto, ZAP, CSV), NVD enrichment (`nvd-lookup`), severity derived from CVSS, analyst-pinned Top 3 with written reasons, management explanations with a verify step. Final data: 8 findings (2 High, 2 Medium, 4 Low) plus 1 documented false positive.
- Attack Evidence: 5-event timeline with Fact/Assumption marking and MITRE ATT&CK IDs.
- AI Security Analyst: preset and free-form questions; answers show cited Evidence ID chips; a verify-before-saving form (verdict, note, confidence, primary evidence). 9 verified answers saved.
- Evidence Locker: EV-004 to EV-019 with source, target, observation, interpretation, confidence and file.
- Reports: executive summary and technical report views, editable sections, export to PDF.
- Dashboard visuals (read-only): risk posture, severity donut, most exposed host, an attack-path diagram that chains the top-ranked open findings (labeled as a risk scenario, not an attack performed), and a network map of the assessor and each host with ports colored by worst open finding.
- Attack Evidence, MITRE ATT&CK coverage: a 14-tactic matrix that lights up the tactics and techniques recorded on the attack events (Discovery: T1018, T1046).
- Evidence chain: from any Evidence ID, a view of every recon item, scan row, finding, AI analysis and report that cites it.
- Presenter mode and search: full-screen presenter mode with arrow-key navigation through the sections, a 12-minute talk timer and the speaker for each section; Ctrl+K search across sections, findings (VULN-) and evidence (EV-).
- Polish: testing-window countdown, live footer ticker of open findings and evidence, short boot screen, 3D depth and motion (all motion turns off when the computer is set to reduce motion). None of these features change data.

## Changes from the original PRD

| Original plan | What we actually did | Why |
|---|---|---|
| AI provider: Claude (Anthropic) | Groq free API (open models); function supports Gemini and Claude as alternatives | Anthropic API required paid credits; Google AI Studio was blocked for the team's account |
| Instructor-provided PCAP for Lab 5 | Public training capture `nmap_standard_scan` (wiki.wireshark.org), labeled as outside scope | No instructor PCAP was supplied |
| Nessus for vulnerability scanning | Nmap safe NSE scripts + Nikto + vendor advisory matching | Nessus Essentials setup failed on the team's PC |
| Practice/example findings during development | Deleted (EV-001 – EV-003, old VULN-001 – 006) and replaced with real lab evidence | Only real evidence may be reported |

## User stories

1. As a security analyst, I want to view discovered ports so that I can understand the exposed attack surface. (Done)
2. As a manager, I want to see findings by severity so that I can prioritize remediation. (Done)
3. As a vulnerability lead, I want to import a real scanner report (Nessus / OpenVAS / Nikto / ZAP / CSV) so that findings are captured accurately without retyping. (Done)
4. As an AI / reporting lead, I want the AI analyst to answer using only our evidence and cite Evidence IDs so that every conclusion is traceable and can be verified. (Done)
5. As a security analyst, I want every finding to link to an Evidence ID in the Evidence Locker so that the assessment is defensible and auditable. (Done)

## Acceptance criteria (final status)

- All required modules are accessible from the main navigation. Met.
- At least one real/supplied evidence item is visible in each technical module. Met (EV-004 to EV-019).
- AI output references evidence and does not invent unsupported facts. Met: citations are enforced, every answer was verified and errors were recorded.
- The final platform can produce or display a clear executive summary. Met (Reports module and export to PDF).
- The platform is demonstrable within the presentation time limit. Met.

## Architecture

Browser SPA → Supabase (Postgres + RLS + Storage) for all records. Three Supabase Edge Functions provide backend logic: `parse-scan` (reads scanner reports), `nvd-lookup` (official CVSS from NIST NVD, cached; it reports "Not retrieved" instead of guessing a score) and `ai-analyst` (evidence-grounded analysis; Groq, Gemini or Claude, key held as a secret).

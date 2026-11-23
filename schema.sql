-- =====================================================================
-- AI Ethical Hacking Command Center: Supabase schema
-- Client: CyberDome Corporation (fictional)
--
-- How to use: paste this whole file into the Supabase SQL editor and run
-- it once. It is safe to run again; nothing is dropped or overwritten.
--
-- Design rule: evidence comes first. Every row in recon, assets,
-- vulnerabilities and attack_events must cite an evidence_id that
-- already exists in the evidence table. An ai_analyses row cites one
-- too when it is about a single item, and lists the ones it drew on in
-- referenced_evidence_ids; an assessment-wide analysis may leave the
-- single evidence_id blank.
-- =====================================================================

create sequence if not exists public.evidence_seq;
create sequence if not exists public.vuln_seq;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end
$$;

-- ---------------------------------------------------------------------
-- engagement: who the client is, what is in scope, when testing is allowed
-- ---------------------------------------------------------------------
create table if not exists public.engagement (
  id                  uuid primary key default gen_random_uuid(),
  client_name         text not null,
  engagement_name     text not null,
  engagement_type     text,
  status              text not null default 'Planning'
                        check (status in ('Planning', 'Active', 'Reporting', 'Closed')),
  start_date          date,
  end_date            date,
  purpose             text,
  scope               text,
  excluded_targets    text,
  prohibited_actions  text[] not null default '{}',
  rules_of_engagement text,
  authorization_ref   text,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now(),
  check (end_date is null or start_date is null or end_date >= start_date)
);

-- Upgrade from the first version of this schema. Renames two columns to
-- match the Engagement page and adds the new ones. Existing values are kept.
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'engagement' and column_name = 'objectives')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'engagement' and column_name = 'purpose') then
    alter table public.engagement rename column objectives to purpose;
  end if;

  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'engagement' and column_name = 'out_of_scope')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'engagement' and column_name = 'excluded_targets') then
    alter table public.engagement rename column out_of_scope to excluded_targets;
  end if;
end
$$;

alter table public.engagement add column if not exists purpose text;
alter table public.engagement add column if not exists excluded_targets text;
alter table public.engagement add column if not exists prohibited_actions text[] not null default '{}';

-- ---------------------------------------------------------------------
-- team_roles: who is on the assessment team and what each person leads
-- ---------------------------------------------------------------------
create table if not exists public.team_roles (
  id          uuid primary key default gen_random_uuid(),
  member_name text not null,
  role        text not null,
  sort_order  integer not null default 0,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- evidence: the source of truth. evidence_id is filled in automatically
-- (EV-001, EV-002, ...) when you leave it blank.
-- ---------------------------------------------------------------------
create table if not exists public.evidence (
  id             uuid primary key default gen_random_uuid(),
  evidence_id    text not null unique
                   default ('EV-' || lpad(nextval('public.evidence_seq')::text, 3, '0'))
                   check (evidence_id ~ '^EV-[0-9]{3,}$'),
  datetime       timestamptz not null default now(),
  source         text not null,
  target_asset   text,
  observation    text not null,
  interpretation text,
  confidence     text not null default 'Requires more evidence'
                   check (confidence in ('High', 'Medium', 'Low', 'Requires more evidence')),
  file_ref       text,
  created_at     timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- recon: what reconnaissance turned up, sorted into four categories
-- ---------------------------------------------------------------------
create table if not exists public.recon (
  id           uuid primary key default gen_random_uuid(),
  evidence_id  text not null
                 references public.evidence (evidence_id) on update cascade on delete restrict,
  item         text not null,
  category     text not null
                 check (category in ('Asset', 'Technology', 'Identity', 'Attack-surface')),
  detail       text,
  analyst_note text,
  created_at   timestamptz not null default now()
);

-- Upgrade from earlier versions of this schema, where recon had
-- target / finding / notes. The columns are renamed so nothing typed
-- into them is lost. Rows that had no category are filed under 'Asset';
-- change them in the table editor if that is wrong.
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'recon' and column_name = 'target')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'recon' and column_name = 'item') then
    alter table public.recon rename column target to item;
  end if;

  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'recon' and column_name = 'finding')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'recon' and column_name = 'detail') then
    alter table public.recon rename column finding to detail;
  end if;

  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'recon' and column_name = 'notes')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'recon' and column_name = 'analyst_note') then
    alter table public.recon rename column notes to analyst_note;
  end if;
end
$$;

alter table public.recon add column if not exists item text;
alter table public.recon add column if not exists category text;
alter table public.recon add column if not exists detail text;
alter table public.recon add column if not exists analyst_note text;
alter table public.recon alter column detail drop not null;

update public.recon
   set item = coalesce(nullif(item, ''), left(detail, 80), 'Unnamed item')
 where item is null or item = '';
update public.recon set category = 'Asset' where category is null;

alter table public.recon alter column item set not null;
alter table public.recon alter column category set not null;

do $$
begin
  if not exists (select 1 from pg_constraint
                 where conname = 'recon_category_check' and conrelid = 'public.recon'::regclass) then
    alter table public.recon add constraint recon_category_check
      check (category in ('Asset', 'Technology', 'Identity', 'Attack-surface'));
  end if;
end
$$;

-- ---------------------------------------------------------------------
-- assets: scan and enumeration results, one row per host and port
-- ---------------------------------------------------------------------
create table if not exists public.assets (
  id                  uuid primary key default gen_random_uuid(),
  evidence_id         text not null
                        references public.evidence (evidence_id) on update cascade on delete restrict,
  hostname            text,
  ip_address          inet,
  port                integer check (port between 1 and 65535),
  protocol            text check (protocol in ('tcp', 'udp', 'sctp')),
  state               text check (state in ('open', 'closed', 'filtered', 'unfiltered',
                                            'open|filtered', 'closed|filtered')),
  service             text,
  version             text,
  risk_note           text,
  needs_investigation boolean not null default false,
  created_at          timestamptz not null default now(),
  constraint assets_host_or_ip_check check (hostname is not null or ip_address is not null)
);

-- Upgrade from earlier versions of this schema, where assets was one row
-- per host. The old notes column becomes risk_note; other old columns
-- are left in place and simply no longer shown.
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'assets' and column_name = 'notes')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'assets' and column_name = 'risk_note') then
    alter table public.assets rename column notes to risk_note;
  end if;
end
$$;

alter table public.assets add column if not exists port integer;
alter table public.assets add column if not exists protocol text;
alter table public.assets add column if not exists state text;
alter table public.assets add column if not exists service text;
alter table public.assets add column if not exists version text;
alter table public.assets add column if not exists risk_note text;
alter table public.assets add column if not exists needs_investigation boolean not null default false;
-- Lab 3: OS observation for the host (from Nmap -O or a service banner).
alter table public.assets add column if not exists os_observation text;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'assets_port_check' and conrelid = 'public.assets'::regclass) then
    alter table public.assets add constraint assets_port_check check (port between 1 and 65535);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'assets_protocol_check' and conrelid = 'public.assets'::regclass) then
    alter table public.assets add constraint assets_protocol_check check (protocol in ('tcp', 'udp', 'sctp'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'assets_state_check' and conrelid = 'public.assets'::regclass) then
    alter table public.assets add constraint assets_state_check
      check (state in ('open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'));
  end if;
  -- "not valid" applies the rule to new rows without rejecting older ones.
  if not exists (select 1 from pg_constraint where conname = 'assets_host_or_ip_check' and conrelid = 'public.assets'::regclass) then
    alter table public.assets add constraint assets_host_or_ip_check
      check (hostname is not null or ip_address is not null) not valid;
  end if;
end
$$;

-- ---------------------------------------------------------------------
-- vulnerabilities: weaknesses identified. vuln_id fills in automatically
-- (VULN-001, VULN-002, ...).
-- ---------------------------------------------------------------------
create table if not exists public.vulnerabilities (
  id                     uuid primary key default gen_random_uuid(),
  vuln_id                text not null unique
                           default ('VULN-' || lpad(nextval('public.vuln_seq')::text, 3, '0')),
  evidence_id            text not null
                           references public.evidence (evidence_id) on update cascade on delete restrict,
  title                  text not null,
  description            text,
  severity               text not null default 'Informational'
                           check (severity in ('Critical', 'High', 'Medium', 'Low', 'Informational')),
  cvss_score             numeric(3, 1) check (cvss_score between 0 and 10),
  cve_id                 text,
  affected_asset         text,
  status                 text not null default 'Open'
                           check (status in ('Open', 'Validated', 'Remediated', 'Accepted risk', 'False positive')),
  impact                 text,
  remediation            text,
  -- Optional. Set 1, 2 or 3 to pin a finding in the Top 3 Priorities, and
  -- say why in one line. Unranked slots are filled by severity, then CVSS.
  priority_rank          smallint check (priority_rank between 1 and 3),
  priority_justification text,
  discovered_at          timestamptz not null default now(),
  created_at             timestamptz not null default now()
);

-- Upgrade from earlier versions of this schema.
alter table public.vulnerabilities add column if not exists impact text;
alter table public.vulnerabilities add column if not exists priority_rank smallint;
alter table public.vulnerabilities add column if not exists priority_justification text;

do $$
begin
  if not exists (select 1 from pg_constraint
                 where conname = 'vulnerabilities_priority_rank_check'
                   and conrelid = 'public.vulnerabilities'::regclass) then
    alter table public.vulnerabilities add constraint vulnerabilities_priority_rank_check
      check (priority_rank between 1 and 3);
  end if;
end
$$;

-- ---------------------------------------------------------------------
-- Vulnerability findings, continued: columns for imported scanner and
-- web-assessment evidence, for CVSS enrichment, and for the management
-- explanation. Added here so earlier databases upgrade in place and
-- nothing already typed into the table is lost.
-- ---------------------------------------------------------------------
alter table public.vulnerabilities add column if not exists host                 text;
alter table public.vulnerabilities add column if not exists port                 integer;
alter table public.vulnerabilities add column if not exists protocol             text;
alter table public.vulnerabilities add column if not exists synopsis             text;
alter table public.vulnerabilities add column if not exists solution             text;
alter table public.vulnerabilities add column if not exists cve_ids              text[] not null default '{}';
alter table public.vulnerabilities add column if not exists cvss_vector          text;
alter table public.vulnerabilities add column if not exists cvss_version         text;
alter table public.vulnerabilities add column if not exists cvss_source          text;   -- 'Scanner' | 'NVD' | 'Manual'
alter table public.vulnerabilities add column if not exists nvd_status           text;   -- 'Retrieved' | 'Not retrieved'
alter table public.vulnerabilities add column if not exists source               text;   -- Nessus | OpenVAS | CSV | Nikto | ZAP | Manual web
alter table public.vulnerabilities add column if not exists source_ref           text;   -- scanner's own id (plugin id, NVT oid)
alter table public.vulnerabilities add column if not exists finding_type         text;
alter table public.vulnerabilities add column if not exists owasp_category       text;
alter table public.vulnerabilities add column if not exists url                  text;
alter table public.vulnerabilities add column if not exists severity_manual      text;   -- used ONLY when there is no CVSS
alter table public.vulnerabilities add column if not exists management_explanation    text;
alter table public.vulnerabilities add column if not exists management_verified       boolean not null default false;
alter table public.vulnerabilities add column if not exists management_verified_by     text;
alter table public.vulnerabilities add column if not exists management_verified_note   text;
alter table public.vulnerabilities add column if not exists management_verified_at     timestamptz;

-- Value guards. "not valid" applies each rule to new rows without
-- rejecting rows that existed before the rule was added.
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_port_check' and conrelid = 'public.vulnerabilities'::regclass) then
    alter table public.vulnerabilities add constraint vulnerabilities_port_check
      check (port is null or port between 1 and 65535) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_protocol_check' and conrelid = 'public.vulnerabilities'::regclass) then
    alter table public.vulnerabilities add constraint vulnerabilities_protocol_check
      check (protocol is null or protocol in ('tcp', 'udp', 'sctp')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_sevman_check' and conrelid = 'public.vulnerabilities'::regclass) then
    alter table public.vulnerabilities add constraint vulnerabilities_sevman_check
      check (severity_manual is null or severity_manual in ('Critical', 'High', 'Medium', 'Low', 'Informational')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'vulnerabilities_nvdstatus_check' and conrelid = 'public.vulnerabilities'::regclass) then
    alter table public.vulnerabilities add constraint vulnerabilities_nvdstatus_check
      check (nvd_status is null or nvd_status in ('Retrieved', 'Not retrieved')) not valid;
  end if;
end
$$;

-- CVSS v3 qualitative band from a base score. A null score has no band.
create or replace function public.cvss_band(score numeric)
returns text language sql immutable set search_path = '' as $$
  select case
    when score is null then null
    when score >= 9.0 then 'Critical'
    when score >= 7.0 then 'High'
    when score >= 4.0 then 'Medium'
    when score >  0.0 then 'Low'
    else 'Informational'
  end
$$;

-- Severity is DERIVED, never hand-typed: a finding with a CVSS base score
-- takes the matching band; one without a score falls back to the analyst's
-- qualitative severity_manual (for web findings that carry no CVSS). The
-- single cve_id (used for the NVD link) and the cve_ids array are kept in
-- step, so filling in either one populates the other.
create or replace function public.vuln_derive_severity()
returns trigger language plpgsql set search_path = '' as $$
begin
  if new.cvss_score is not null then
    new.severity := public.cvss_band(new.cvss_score);
  else
    new.severity := coalesce(new.severity_manual, new.severity, 'Informational');
  end if;
  if (new.cve_ids is null or cardinality(new.cve_ids) = 0) and new.cve_id is not null then
    new.cve_ids := array[new.cve_id];
  elsif new.cve_id is null and new.cve_ids is not null and cardinality(new.cve_ids) > 0 then
    new.cve_id := new.cve_ids[1];
  end if;
  return new;
end
$$;

drop trigger if exists vulnerabilities_derive_severity on public.vulnerabilities;
create trigger vulnerabilities_derive_severity
  before insert or update on public.vulnerabilities
  for each row execute function public.vuln_derive_severity();

-- Re-derive severity for any rows saved before the trigger existed. Safe
-- to repeat: only rows whose stored severity disagrees with their CVSS change.
update public.vulnerabilities
   set severity = public.cvss_band(cvss_score)
 where cvss_score is not null
   and severity is distinct from public.cvss_band(cvss_score);

-- ---------------------------------------------------------------------
-- cve_cache: one row per CVE looked up at NVD, written by the nvd-lookup
-- function so the same CVE is fetched only once. status is 'Retrieved'
-- when NVD returned a CVSS v3 metric, or 'Not retrieved' when it did not
-- (the function never fabricates a score or description).
-- ---------------------------------------------------------------------
create table if not exists public.cve_cache (
  cve_id          text primary key check (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  cvss_v31_score  numeric(3, 1) check (cvss_v31_score is null or cvss_v31_score between 0 and 10),
  cvss_v31_vector text,
  cvss_version    text,
  description     text,
  status          text not null default 'Not retrieved' check (status in ('Retrieved', 'Not retrieved')),
  source          text not null default 'NVD',
  retrieved_at    timestamptz not null default now()
);
alter table public.cve_cache add column if not exists cvss_version text;

-- ---------------------------------------------------------------------
-- vuln_import_staging: parsed records waiting for review. The parse-scan
-- function returns findings, the app saves them here with a batch_id, you
-- accept or reject each one, and committing copies the accepted rows into
-- vulnerabilities. parse_error holds the message for any record that could
-- not be read, so nothing silently disappears.
-- ---------------------------------------------------------------------
create table if not exists public.vuln_import_staging (
  id                uuid primary key default gen_random_uuid(),
  batch_id          uuid not null,
  evidence_id       text references public.evidence (evidence_id) on update cascade on delete set null,
  source_format     text,
  record_index      integer,
  title             text,
  description       text,
  synopsis          text,
  solution          text,
  host              text,
  port              integer,
  protocol          text,
  cvss_score        numeric(3, 1),
  cvss_vector       text,
  cve_ids           text[] not null default '{}',
  severity_raw      text,
  finding_type      text,
  owasp_category    text,
  url               text,
  source_ref        text,
  parse_error       text,
  accepted          boolean not null default true,
  committed         boolean not null default false,
  committed_vuln_id text,
  created_at        timestamptz not null default now()
);
create index if not exists vuln_import_staging_batch_idx on public.vuln_import_staging (batch_id);

-- ---------------------------------------------------------------------
-- attack_events: the attack timeline. Each event says what was observed,
-- what the student makes of it, and whether that reading is fact or assumption.
-- ---------------------------------------------------------------------
create table if not exists public.attack_events (
  id                     uuid primary key default gen_random_uuid(),
  evidence_id            text not null
                           references public.evidence (evidence_id) on update cascade on delete restrict,
  event_time             timestamptz not null default now(),
  observed_event         text not null,
  student_interpretation text,
  -- Fact = shown directly by the evidence. Assumption = your reading of it.
  basis                  text not null default 'Assumption'
                           check (basis in ('Fact', 'Assumption')),
  -- True where the event is uncertain and more evidence is needed.
  needs_more_evidence    boolean not null default false,
  target_asset           text,
  technique              text,
  mitre_attack_id        text,
  tool                   text,
  outcome                text check (outcome in ('Successful', 'Partial', 'Failed', 'Blocked')),
  created_at             timestamptz not null default now()
);

-- Upgrade from earlier versions of this schema. The old action_taken
-- column becomes observed_event; technique and outcome become optional.
-- Rows that had no fact/assumption label start as 'Assumption'.
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'attack_events' and column_name = 'action_taken')
     and not exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'attack_events' and column_name = 'observed_event') then
    alter table public.attack_events rename column action_taken to observed_event;
  end if;
end
$$;

alter table public.attack_events add column if not exists observed_event text;
alter table public.attack_events add column if not exists student_interpretation text;
alter table public.attack_events add column if not exists basis text;
alter table public.attack_events add column if not exists needs_more_evidence boolean not null default false;
alter table public.attack_events alter column technique drop not null;
alter table public.attack_events alter column outcome drop not null;
alter table public.attack_events alter column outcome drop default;

update public.attack_events
   set observed_event = coalesce(nullif(observed_event, ''), technique, 'Not described')
 where observed_event is null or observed_event = '';
update public.attack_events set basis = 'Assumption' where basis is null;

alter table public.attack_events alter column observed_event set not null;
alter table public.attack_events alter column basis set not null;
alter table public.attack_events alter column basis set default 'Assumption';

do $$
begin
  if not exists (select 1 from pg_constraint
                 where conname = 'attack_events_basis_check' and conrelid = 'public.attack_events'::regclass) then
    alter table public.attack_events add constraint attack_events_basis_check
      check (basis in ('Fact', 'Assumption'));
  end if;
end
$$;

-- ---------------------------------------------------------------------
-- ai_analyses: saved AI output and the student's check of it.
-- module says which page the analysis belongs to, for example 'Recon'.
-- ---------------------------------------------------------------------
create table if not exists public.ai_analyses (
  id                 uuid primary key default gen_random_uuid(),
  evidence_id        text
                       references public.evidence (evidence_id) on update cascade on delete restrict,
  referenced_evidence_ids text[] not null default '{}',
  module             text,
  analysis_type      text,
  model              text,
  prompt_summary     text,
  ai_output          text not null,
  confidence         text not null default 'Requires more evidence'
                       check (confidence in ('High', 'Medium', 'Low', 'Requires more evidence')),
  analyst_validation text not null default 'Unreviewed'
                       check (analyst_validation in ('Unreviewed', 'Confirmed', 'Partially confirmed', 'Rejected')),
  verification_note  text,
  validated_by       text,
  created_at         timestamptz not null default now()
);

alter table public.ai_analyses add column if not exists module text;
alter table public.ai_analyses add column if not exists verification_note text;
alter table public.ai_analyses add column if not exists referenced_evidence_ids text[] not null default '{}';
-- An AI analysis may span the whole assessment, so its single evidence_id is optional.
alter table public.ai_analyses alter column evidence_id drop not null;

-- ---------------------------------------------------------------------
-- iocs: indicators of compromise, each citing the evidence that shows it
-- ---------------------------------------------------------------------
create table if not exists public.iocs (
  id          uuid primary key default gen_random_uuid(),
  indicator   text not null,
  evidence_id text not null
                references public.evidence (evidence_id) on update cascade on delete restrict,
  assessment  text not null default 'Requires more evidence'
                check (assessment in ('Suspicious', 'Benign', 'Requires more evidence')),
  notes       text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- reports: deliverables. evidence_id is optional here because a report
-- usually draws on many evidence items.
-- ---------------------------------------------------------------------
create table if not exists public.reports (
  id          uuid primary key default gen_random_uuid(),
  evidence_id text
                references public.evidence (evidence_id) on update cascade on delete restrict,
  title       text not null,
  report_type text,
  version     text not null default '0.1',
  status      text not null default 'Draft'
                check (status in ('Draft', 'In review', 'Final')),
  summary     text,
  author      text,
  file_ref    text,
  -- Editable narrative sections for the Reports page (executive and
  -- technical), keyed by section. Parts left out are generated live from
  -- the other tables, so an untouched report tracks the latest data.
  content     jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

alter table public.reports add column if not exists content jsonb not null default '{}'::jsonb;

-- ---------------------------------------------------------------------
-- Indexes on the evidence links
-- ---------------------------------------------------------------------
create index if not exists recon_evidence_id_idx           on public.recon (evidence_id);
create index if not exists assets_evidence_id_idx          on public.assets (evidence_id);
create index if not exists vulnerabilities_evidence_id_idx on public.vulnerabilities (evidence_id);
create index if not exists attack_events_evidence_id_idx   on public.attack_events (evidence_id);
create index if not exists ai_analyses_evidence_id_idx     on public.ai_analyses (evidence_id);
create index if not exists reports_evidence_id_idx         on public.reports (evidence_id);
create index if not exists iocs_evidence_id_idx            on public.iocs (evidence_id);
create index if not exists ai_analyses_module_idx          on public.ai_analyses (module);
create index if not exists attack_events_event_time_idx    on public.attack_events (event_time);
create index if not exists evidence_datetime_idx           on public.evidence (datetime desc);

-- ---------------------------------------------------------------------
-- Keep updated_at current
-- ---------------------------------------------------------------------
drop trigger if exists engagement_set_updated_at on public.engagement;
create trigger engagement_set_updated_at
  before update on public.engagement
  for each row execute function public.set_updated_at();

drop trigger if exists reports_set_updated_at on public.reports;
create trigger reports_set_updated_at
  before update on public.reports
  for each row execute function public.set_updated_at();

drop trigger if exists iocs_set_updated_at on public.iocs;
create trigger iocs_set_updated_at
  before update on public.iocs
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------
-- Access rules (row-level security)
--   Read:  signed-in teammates only. The anon key is public by design, so
--          reading is locked to logged-in users; anyone opening the app
--          without signing in sees empty tables. Give the instructor (or
--          any demo viewer) a team login.
--   Write: signed-in teammates only, with separate insert / update /
--          delete rules. Create an account for each teammate in the
--          project's Authentication settings, and turn off public sign-ups
--          there so nobody else can create one.
-- Matches the live project (migration
-- 20261117211950_separate_team_write_policies_and_index_staging_evidence
-- plus the read rule restricted to authenticated users).
-- ---------------------------------------------------------------------
do $$
declare
  t text;
begin
  foreach t in array array[
    'engagement', 'evidence', 'recon', 'assets',
    'vulnerabilities', 'attack_events', 'ai_analyses', 'reports',
    'team_roles', 'iocs', 'cve_cache', 'vuln_import_staging'
  ]
  loop
    execute format('alter table public.%I enable row level security', t);

    execute format('drop policy if exists "Read for the app" on public.%I', t);
    execute format(
      'create policy "Read for the app" on public.%I for select to authenticated using (true)', t);

    -- Replaced by the three separate rules below.
    execute format('drop policy if exists "Write for signed-in users" on public.%I', t);

    execute format('drop policy if exists "Team insert" on public.%I', t);
    execute format(
      'create policy "Team insert" on public.%I for insert to authenticated with check (true)', t);
    execute format('drop policy if exists "Team update" on public.%I', t);
    execute format(
      'create policy "Team update" on public.%I for update to authenticated using (true) with check (true)', t);
    execute format('drop policy if exists "Team delete" on public.%I', t);
    execute format(
      'create policy "Team delete" on public.%I for delete to authenticated using (true)', t);

    execute format('grant select, insert, update, delete on public.%I to authenticated', t);
  end loop;
end
$$;

create index if not exists vuln_import_staging_evidence_id_idx on public.vuln_import_staging (evidence_id);

grant usage, select on sequence public.evidence_seq, public.vuln_seq to authenticated;

-- ---------------------------------------------------------------------
-- Storage for evidence files and screenshots.
-- Creates a private 'evidence-files' bucket and lets signed-in users
-- read, add and remove objects in it. The whole block is skipped when
-- the storage schema isn't present (for example when testing this file
-- outside Supabase), and any permission issue is reported, not fatal.
-- ---------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from information_schema.schemata where schema_name = 'storage') then
    return;
  end if;
  begin
    insert into storage.buckets (id, name, public)
    values ('evidence-files', 'evidence-files', false)
    on conflict (id) do nothing;

    execute 'drop policy if exists "Evidence files: read for signed-in" on storage.objects';
    execute 'create policy "Evidence files: read for signed-in" on storage.objects '
         || 'for select to authenticated using (bucket_id = ''evidence-files'')';

    execute 'drop policy if exists "Evidence files: add for signed-in" on storage.objects';
    execute 'create policy "Evidence files: add for signed-in" on storage.objects '
         || 'for insert to authenticated with check (bucket_id = ''evidence-files'')';

    execute 'drop policy if exists "Evidence files: remove for signed-in" on storage.objects';
    execute 'create policy "Evidence files: remove for signed-in" on storage.objects '
         || 'for delete to authenticated using (bucket_id = ''evidence-files'')';
  exception when others then
    raise notice 'Evidence-files storage setup skipped (%). Create a private bucket named evidence-files and its signed-in read/write policies from the Storage dashboard.', sqlerrm;
  end;
end
$$;

-- ---------------------------------------------------------------------
-- Starting records. Each is only inserted when its table is empty, so
-- anything you have edited in the app is left alone.
-- ---------------------------------------------------------------------
insert into public.engagement
  (client_name, engagement_name, engagement_type, status, start_date, end_date,
   purpose, scope, excluded_targets, prohibited_actions)
select
  'CyberDome Corporation',
  'CyberDome Corporation security assessment',
  'Authorized lab penetration test',
  'Active',
  date '2026-09-21',
  date '2026-11-22',
  'Authorized security assessment of the CyberDome Corporation lab network: find, validate and document weaknesses, with every finding tied to recorded evidence.',
  '192.168.56.0/24 lab network',
  'Everything outside 192.168.56.0/24, including public and production systems.',
  array['Denial of service (DoS)', 'Destructive testing', 'Persistence',
        'Credential theft', 'Exfiltration', 'Public systems']
where not exists (select 1 from public.engagement);

-- If the engagement record came from the first version of this schema,
-- fill in the fields that did not exist then. Only empty fields change.
update public.engagement set
  purpose = coalesce(purpose,
    'Authorized security assessment of the CyberDome Corporation lab network: find, validate and document weaknesses, with every finding tied to recorded evidence.'),
  excluded_targets = coalesce(excluded_targets,
    'Everything outside 192.168.56.0/24, including public and production systems.'),
  prohibited_actions = case when cardinality(prohibited_actions) = 0
    then array['Denial of service (DoS)', 'Destructive testing', 'Persistence',
               'Credential theft', 'Exfiltration', 'Public systems']
    else prohibited_actions end,
  scope = case when scope = '192.168.56.0/24 (instructor-approved lab network)'
    then '192.168.56.0/24 lab network' else scope end
where purpose is null
   or excluded_targets is null
   or cardinality(prohibited_actions) = 0
   or scope = '192.168.56.0/24 (instructor-approved lab network)';

insert into public.team_roles (member_name, role, sort_order)
select v.member_name, v.role, v.sort_order
from (values
  ('Ryan',   'Recon Lead',              1),
  ('Olma',   'Network Assessment Lead', 2),
  ('Elnathan', 'Vulnerability Lead',    3),
  ('Darien', 'AI/Reporting Lead',       4),
  ('Jacob',  'Demo Lead',               5)
) as v (member_name, role, sort_order)
where not exists (select 1 from public.team_roles);

create table if not exists scan_run (
  id uuid primary key,
  created_at timestamptz not null,
  base_ref varchar(200) not null,
  head_ref varchar(200) not null,
  status varchar(32) not null,
  findings_count int not null
);

create table if not exists scan_finding (
  id uuid primary key,
  scan_run_id uuid not null references scan_run(id) on delete cascade,
  rule_id varchar(100) not null,
  severity varchar(32) not null,
  location_type varchar(32) not null,
  file_path text,
  commit_id varchar(60),
  line_number int,
  redacted_snippet text not null,
  guidance text not null
);

create index if not exists ix_scan_finding_run on scan_finding(scan_run_id);

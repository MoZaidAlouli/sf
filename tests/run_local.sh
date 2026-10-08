#!/usr/bin/env bash
# Runs schema.sql plus security_test.sql against a throwaway local PostgreSQL (15+).
# Usage: sudo -u postgres bash supabase/tests/run_local.sh
set -euo pipefail
DB=soul_registration_test
HERE="$(cd "$(dirname "$0")" && pwd)"
psql -v ON_ERROR_STOP=1 -q -d postgres <<SQL
drop database if exists $DB;
create database $DB;
SQL
psql -v ON_ERROR_STOP=1 -q -d "$DB" <<'SQL'
-- Roles that exist by default on Supabase.
do $$ begin
  if not exists (select from pg_roles where rolname = 'anon') then create role anon nologin; end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then create role authenticated nologin; end if;
  if not exists (select from pg_roles where rolname = 'service_role') then create role service_role nologin bypassrls; end if;
end $$;
grant usage on schema public to anon, authenticated, service_role;
SQL
psql -v ON_ERROR_STOP=1 -q -d "$DB" -f "$HERE/../schema.sql"
psql -v ON_ERROR_STOP=1 -d "$DB" -f "$HERE/security_test.sql"

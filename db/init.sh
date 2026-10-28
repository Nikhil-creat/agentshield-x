#!/bin/sh
# Runs once on first Postgres start (docker-entrypoint-initdb.d). Creates least-privilege roles, then the schema.
set -eu

: "${POSTGRES_WRITER_PASSWORD:?}" "${POSTGRES_AUDITOR_PASSWORD:?}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v writer_pw="$POSTGRES_WRITER_PASSWORD" -v auditor_pw="$POSTGRES_AUDITOR_PASSWORD" <<'SQL'
-- NOLOGIN-less app roles with no inherited privileges; passwords come from the environment.
CREATE ROLE shield_writer  LOGIN PASSWORD :'writer_pw'  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE shield_auditor LOGIN PASSWORD :'auditor_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
REVOKE ALL ON DATABASE agentshield FROM PUBLIC;
GRANT CONNECT ON DATABASE agentshield TO shield_writer, shield_auditor;
GRANT USAGE ON SCHEMA public TO shield_writer, shield_auditor;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f /schema/init.sql

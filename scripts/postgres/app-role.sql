-- Least-privilege database role for the Aegis control plane.
--
-- Run this as a superuser once per database, AFTER `alembic upgrade head`.
--
-- Why it matters: PostgreSQL superusers bypass row-level security entirely, even on tables
-- with FORCE ROW LEVEL SECURITY. Running the application as a superuser silently removes
-- the second of the two tenant-isolation controls in ADR-0003 while every policy still
-- appears to be in place. The API refuses to start in staging or production when its role
-- is a superuser, and logs a warning elsewhere.
--
-- Usage:
--   psql -v role_password="'a-strong-password'" -f scripts/postgres/app-role.sql aegis

\set app_role aegis_app

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_app') THEN
        CREATE ROLE aegis_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$$;

ALTER ROLE aegis_app PASSWORD :role_password;

GRANT CONNECT ON DATABASE :"DBNAME" TO aegis_app;
GRANT USAGE ON SCHEMA public TO aegis_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegis_app;

-- The audit chain is append-only. The trigger installed by migration 0001 rejects UPDATE
-- and DELETE; revoking the privileges as well means two independent controls must fail
-- before an entry can be altered (threat T-11).
REVOKE UPDATE, DELETE ON audit_events FROM aegis_app;

-- Triage comments are the written record of how a dismissal was decided. After an incident
-- that record is exactly what an investigation reads, and exactly what someone would most
-- want to change. The trigger in migration 0002 refuses the mutation regardless of role;
-- this revoke means the application cannot even attempt it.
REVOKE UPDATE, DELETE ON finding_comments FROM aegis_app;

-- Evidence of something that happened cannot retrospectively have happened differently.
REVOKE UPDATE, DELETE ON finding_occurrences FROM aegis_app;

-- Tables created by future migrations inherit the same grants.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO aegis_app;

-- Migrations continue to run as the owner; only the application connects as aegis_app.

-- Extensions required by the Aegis control plane.
-- Executed once, on first initialization of the data directory.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";      -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS "citext";        -- case-insensitive email addresses
CREATE EXTENSION IF NOT EXISTS "pg_trgm";       -- trigram search over names and paths
CREATE EXTENSION IF NOT EXISTS "btree_gin";     -- composite GIN indexes for tag filtering
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- pgvector powers the RAG corpus from Phase 6. Created here so the migration that
-- introduces embedding columns does not need superuser rights at deploy time.
CREATE EXTENSION IF NOT EXISTS "vector";

-- Dedicated test database so the integration suite never touches development data.
SELECT 'CREATE DATABASE aegis_test OWNER aegis'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aegis_test')\gexec

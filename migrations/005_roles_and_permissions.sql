-- Olympus Phase 0.5 Migration 005
-- Database roles and least-privilege grants

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'migrator') THEN
        CREATE ROLE migrator;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'writer') THEN
        CREATE ROLE writer;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor') THEN
        CREATE ROLE auditor;
    END IF;
END;
$$;

DO $$
DECLARE
    dbname text;
BEGIN
    SELECT current_database() INTO dbname;
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO migrator, writer, auditor', dbname);
END;
$$;

GRANT USAGE ON SCHEMA public TO migrator, writer, auditor;
GRANT CREATE ON SCHEMA public TO migrator;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM writer;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM auditor;

GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO auditor;

REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM writer;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT, INSERT ON TABLES TO writer;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT ON TABLES TO auditor;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT ALL ON TABLES TO migrator;

COMMENT ON ROLE migrator IS 'Applies schema migrations and DDL changes for Olympus.';
COMMENT ON ROLE writer IS 'Append-only writer role (INSERT + minimal SELECT).';
COMMENT ON ROLE auditor IS 'Read-only auditor role (SELECT only).';

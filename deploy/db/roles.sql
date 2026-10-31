-- HELIOS database roles. Run once per database, as its administrator (the
-- postgres superuser, or the RDS / Cloud SQL master user), before the first
-- migration. Passwords come from psql variables:
--   psql "$ADMIN_URL" -v owner_password=... -v app_password=... -v db=helios -f deploy/db/roles.sql
--
--   helios_owner  owns the schema; runs migrations (the migrate job only).
--   helios_app    what the web and worker containers sign in as: reads and
--                 writes rows, can't create, alter or drop anything, isn't a
--                 superuser and doesn't bypass row-level security, so the
--                 per-client policies hold for it. Monthly event partitions
--                 are made through two functions that run as the owner.
-- grants.sql (after each migration) narrows it further.

SELECT format('CREATE ROLE helios_owner LOGIN PASSWORD %L', :'owner_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'helios_owner') \gexec
SELECT format('CREATE ROLE helios_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'helios_app') \gexec
ALTER ROLE helios_owner NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE helios_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- Sessions that hang hold locks: cut them off.
ALTER ROLE helios_app SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE helios_app SET statement_timeout = '120s';

-- The owner role needs to be grantable by the admin (RDS's master isn't a superuser).
GRANT helios_owner TO CURRENT_USER;
SELECT format('ALTER DATABASE %I OWNER TO helios_owner', :'db') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \gexec
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO helios_app', :'db') \gexec

\connect :db
ALTER SCHEMA public OWNER TO helios_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO helios_app;
-- Everything the owner creates from now on is usable, not alterable, by the app.
ALTER DEFAULT PRIVILEGES FOR ROLE helios_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO helios_app;
ALTER DEFAULT PRIVILEGES FOR ROLE helios_owner IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO helios_app;
ALTER DEFAULT PRIVILEGES FOR ROLE helios_owner IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE helios_owner IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO helios_app;

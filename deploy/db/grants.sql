-- Run as helios_owner after every migration (the migrate job does):
--   npx prisma db execute --file deploy/db/grants.sql --schema prisma/schema.prisma
-- Idempotent. Re-applies what the app role may do on what migrations made.

GRANT USAGE ON SCHEMA public TO helios_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO helios_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO helios_app;
-- Migration history is the owner's business.
REVOKE INSERT, UPDATE, DELETE ON _prisma_migrations FROM helios_app;

-- The audit chain is append-only for the app: it can add entries and read
-- them, never change or remove one, whatever happens to the app.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM helios_app;

-- Partition maintenance runs as the owner, callable by the app only.
REVOKE EXECUTE ON FUNCTION helios_ensure_event_partition(timestamp) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION helios_drop_event_partition(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION helios_ensure_event_partition(timestamp) TO helios_app;
GRANT EXECUTE ON FUNCTION helios_drop_event_partition(text) TO helios_app;

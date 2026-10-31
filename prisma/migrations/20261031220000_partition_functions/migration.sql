-- The retention job creates and drops monthly partitions of security_events
-- (lib/retention/partitions.ts). It does that through these two functions,
-- which run as their owner (the role that runs migrations), so the role the
-- application signs in with needs no right to create, alter or drop tables
-- (deploy/db/roles.sql). Both refuse to run inside a client-scoped
-- transaction: they work on every client's rows, and the check for case
-- evidence must see all of them.

CREATE OR REPLACE FUNCTION helios_ensure_event_partition(month_start timestamp)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
  from_ts timestamp := date_trunc('month', month_start);
  to_ts timestamp := date_trunc('month', month_start) + interval '1 month';
  part text := 'security_events_' || to_char(date_trunc('month', month_start), 'YYYY_MM');
  stray boolean;
BEGIN
  IF coalesce(current_setting('helios.tenant_id', true), '') <> '' THEN
    RAISE EXCEPTION 'partition changes can''t run scoped to one client';
  END IF;
  -- One partition change at a time (the same lock the app used before).
  PERFORM pg_advisory_xact_lock(727201031);
  IF to_regclass(format('%I', part)) IS NOT NULL THEN
    RETURN false;
  END IF;
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM security_events_default WHERE "timestamp" >= %L AND "timestamp" < %L)', from_ts, to_ts) INTO stray;
  IF stray THEN
    -- Rows for the month already sit in the default partition: move them.
    EXECUTE format('CREATE TABLE %I (LIKE security_events INCLUDING DEFAULTS)', part);
    EXECUTE format('INSERT INTO %I SELECT * FROM security_events_default WHERE "timestamp" >= %L AND "timestamp" < %L', part, from_ts, to_ts);
    EXECUTE format('DELETE FROM security_events_default WHERE "timestamp" >= %L AND "timestamp" < %L', from_ts, to_ts);
    EXECUTE format('ALTER TABLE security_events ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L)', part, from_ts, to_ts);
  ELSE
    EXECUTE format('CREATE TABLE %I PARTITION OF security_events FOR VALUES FROM (%L) TO (%L)', part, from_ts, to_ts);
  END IF;
  -- The parent's row-level policy, so a tenant-scoped connection can't read
  -- the partition directly to get around it.
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', part);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', part);
  EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true)) WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))$p$, part);
  RETURN true;
END
$$;

-- Drops a month's partition and returns how many events went with it, or
-- NULL when it was kept because a case has taken any of its events. The
-- check runs under the partition's exclusive lock, so no event can be
-- attached to a case while it runs.
CREATE OR REPLACE FUNCTION helios_drop_event_partition(part text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
  rel regclass;
  evidence boolean;
  n bigint;
BEGIN
  IF part !~ '^security_events_[0-9]{4}_[0-9]{2}$' THEN
    RAISE EXCEPTION '% isn''t a monthly event partition', part;
  END IF;
  IF coalesce(current_setting('helios.tenant_id', true), '') <> '' THEN
    RAISE EXCEPTION 'partition changes can''t run scoped to one client';
  END IF;
  PERFORM pg_advisory_xact_lock(727201031);
  rel := to_regclass(format('%I', part));
  IF rel IS NULL THEN
    RETURN 0;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_inherits WHERE inhrelid = rel AND inhparent = 'security_events'::regclass) THEN
    RAISE EXCEPTION '% isn''t a partition of security_events', part;
  END IF;
  EXECUTE format('LOCK TABLE %I IN ACCESS EXCLUSIVE MODE', part);
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I WHERE "caseId" IS NOT NULL)', part) INTO evidence;
  IF evidence THEN
    RETURN NULL;
  END IF;
  EXECUTE format('SELECT count(*) FROM %I', part) INTO n;
  EXECUTE format('ALTER TABLE security_events DETACH PARTITION %I', part);
  EXECUTE format('DROP TABLE %I', part);
  RETURN n;
END
$$;

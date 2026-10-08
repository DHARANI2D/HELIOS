-- Real bug found while adding tests for this phase: audit_logs.caseId's
-- FK used ON DELETE SET NULL (Prisma's implicit default for an optional
-- relation). Deleting a Case retroactively nulls that column on any
-- AuditLog row referencing it -- but currentHash was computed from the
-- REAL caseId at write time, so the row becomes permanently
-- unverifiable the moment that happens. Nothing in the app ever deletes
-- a Case, so this was latent -- but the DB should refuse the deletion
-- outright rather than silently corrupt the one thing the audit trail
-- exists to guarantee.
ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_caseId_fkey";
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

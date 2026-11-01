-- AI-led initial containment by default for new clients and plans; existing
-- rows keep what was agreed (changing them goes through change control).

-- AlterTable
ALTER TABLE "service_plans" ALTER COLUMN "defaultAutonomyCap" SET DEFAULT 'AUTO_CONTAIN';

-- AlterTable
ALTER TABLE "tenants" ALTER COLUMN "aiAutonomyCap" SET DEFAULT 'AUTO_CONTAIN';


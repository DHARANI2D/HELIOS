import { INDUSTRIES } from "@/lib/assets/estate";
import { rulebookSchema, type Rulebook } from "@/lib/rulebook/schema";

// Starting points for a client's rulebook, by industry. Each one only
// pre-fills sensible rules; the client edits them against their own
// inventory and signs the result. Pure.

export const TEMPLATES = {
  general: { label: "General business", note: "Approval for containment, never-isolate domain controllers, two people to disable an account." },
  healthcare: { label: "Healthcare", note: "Medical devices and clinical systems never isolated; containment held for approval; strict PII handling." },
  finance: { label: "Finance & insurance", note: "Tier-1 core systems, two-person rule for account and host actions, regulated-entity reporting on." },
  manufacturing: { label: "Manufacturing & energy", note: "PLCs, SCADA and plant systems never touched; actions outside shifts need approval." },
  retail: { label: "Retail & e-commerce", note: "Storefront servers tier-1; change freezes in peak season; quick automatic blocking of bad IPs." },
  technology: { label: "Technology & software", note: "Fast automatic containment on laptops at high severity; build systems tier-1." },
} as const;
export type TemplateKey = keyof typeof TEMPLATES;

export function templateFor(industry: keyof typeof INDUSTRIES | string | null | undefined): TemplateKey {
  if (industry === "healthcare") return "healthcare";
  if (industry === "finance") return "finance";
  if (industry === "manufacturing" || industry === "energy") return "manufacturing";
  if (industry === "retail") return "retail";
  if (industry === "technology") return "technology";
  return "general";
}

const DC = { kind: "assetType" as const, value: "domain_controller", note: "Domain controllers" };
const BREAK_GLASS = ["break-glass*", "breakglass*", "emergency-admin*"];
const SERVICE = ["svc-*", "svc_*", "*$"];

export function buildTemplate(key: TemplateKey, timeZone = "Asia/Kolkata"): Rulebook {
  const base = {
    assets: { crownJewels: [DC, { kind: "assetType", value: "backup_server", note: "Backup servers" }], neverIsolate: [DC] },
    identities: { vip: [], breakGlass: BREAK_GLASS, service: SERVICE },
    schedule: { timeZone },
    blastRadius: { maxActionsPerHour: 5, maxHostsIsolated: 3, twoPerson: ["DISABLE_USER"] },
  };
  switch (key) {
    case "healthcare":
      return rulebookSchema.parse({
        ...base,
        assets: {
          crownJewels: [...base.assets.crownJewels, { kind: "assetGroup", value: "iot_ot", note: "Clinical and building systems" }, { kind: "assetType", value: "database_server", note: "Patient records" }],
          neverIsolate: [DC, { kind: "assetType", value: "medical", note: "Medical devices (patient safety)" }, { kind: "assetType", value: "building", note: "Building management" }],
        },
        actions: {
          ISOLATE_HOST: { mode: "approve" },
          BLOCK_IP: { mode: "auto", autoFrom: "HIGH" },
          QUARANTINE_FILE: { mode: "auto", autoFrom: "HIGH" },
          BLOCK_SENDER: { mode: "auto", autoFrom: "MEDIUM" },
          KILL_PROCESS: { mode: "approve" },
          DISABLE_USER: { mode: "approve" },
          COLLECT_LOGS: { mode: "auto", autoFrom: "MEDIUM" },
          REVOKE_AGENT: { mode: "approve" },
        },
        blastRadius: { maxActionsPerHour: 3, maxHostsIsolated: 2, twoPerson: ["DISABLE_USER", "ISOLATE_HOST"] },
        dataHandling: { residency: "any", redactPii: true },
        obligations: { regulatedEntity: true, dpdpFiduciary: true },
      });
    case "finance":
      return rulebookSchema.parse({
        ...base,
        assets: {
          crownJewels: [...base.assets.crownJewels, { kind: "assetType", value: "database_server", note: "Core banking and ledgers" }, { kind: "assetType", value: "web_server", note: "Customer-facing services" }],
          neverIsolate: [DC],
        },
        actions: {
          ISOLATE_HOST: { mode: "auto", autoFrom: "CRITICAL" },
          BLOCK_IP: { mode: "auto", autoFrom: "HIGH" },
          QUARANTINE_FILE: { mode: "auto", autoFrom: "HIGH" },
          BLOCK_SENDER: { mode: "auto", autoFrom: "MEDIUM" },
          KILL_PROCESS: { mode: "approve" },
          DISABLE_USER: { mode: "approve" },
          COLLECT_LOGS: { mode: "auto", autoFrom: "MEDIUM" },
          REVOKE_AGENT: { mode: "approve" },
        },
        blastRadius: { maxActionsPerHour: 5, maxHostsIsolated: 3, twoPerson: ["DISABLE_USER", "ISOLATE_HOST"] },
        dataHandling: { residency: "any", redactPii: true },
        obligations: { regulatedEntity: true, dpdpFiduciary: true },
      });
    case "manufacturing":
      return rulebookSchema.parse({
        ...base,
        assets: {
          crownJewels: [...base.assets.crownJewels, { kind: "assetGroup", value: "iot_ot", note: "Plant systems" }],
          neverIsolate: [DC, { kind: "assetType", value: "plc", note: "PLCs" }, { kind: "assetType", value: "scada", note: "SCADA / HMI" }, { kind: "assetType", value: "sensor", note: "Industrial equipment" }],
        },
        actions: {
          ISOLATE_HOST: { mode: "approve" },
          BLOCK_IP: { mode: "auto", autoFrom: "HIGH" },
          QUARANTINE_FILE: { mode: "auto", autoFrom: "HIGH" },
          BLOCK_SENDER: { mode: "auto", autoFrom: "MEDIUM" },
          KILL_PROCESS: { mode: "approve" },
          DISABLE_USER: { mode: "approve" },
          COLLECT_LOGS: { mode: "auto", autoFrom: "MEDIUM" },
          REVOKE_AGENT: { mode: "approve" },
        },
        schedule: { timeZone, businessDays: [1, 2, 3, 4, 5, 6], businessStart: "06:00", businessEnd: "22:00", outOfHours: "approve" },
      });
    case "retail":
      return rulebookSchema.parse({
        ...base,
        assets: { crownJewels: [...base.assets.crownJewels, { kind: "assetType", value: "web_server", note: "Storefront" }, { kind: "assetType", value: "database_server", note: "Orders and payments" }], neverIsolate: [DC] },
        actions: {
          ISOLATE_HOST: { mode: "auto", autoFrom: "CRITICAL" },
          BLOCK_IP: { mode: "auto", autoFrom: "MEDIUM" },
          QUARANTINE_FILE: { mode: "auto", autoFrom: "HIGH" },
          BLOCK_SENDER: { mode: "auto", autoFrom: "MEDIUM" },
          KILL_PROCESS: { mode: "approve" },
          DISABLE_USER: { mode: "approve" },
          COLLECT_LOGS: { mode: "auto", autoFrom: "MEDIUM" },
          REVOKE_AGENT: { mode: "approve" },
        },
      });
    case "technology":
      return rulebookSchema.parse({
        ...base,
        assets: { crownJewels: [...base.assets.crownJewels, { kind: "assetType", value: "repository", note: "Source code" }, { kind: "assetType", value: "ci_runner", note: "Build systems" }], neverIsolate: [DC] },
        actions: {
          ISOLATE_HOST: { mode: "auto", autoFrom: "HIGH" },
          BLOCK_IP: { mode: "auto", autoFrom: "HIGH" },
          QUARANTINE_FILE: { mode: "auto", autoFrom: "HIGH" },
          BLOCK_SENDER: { mode: "auto", autoFrom: "MEDIUM" },
          KILL_PROCESS: { mode: "approve" },
          DISABLE_USER: { mode: "approve" },
          COLLECT_LOGS: { mode: "auto", autoFrom: "MEDIUM" },
          REVOKE_AGENT: { mode: "auto", autoFrom: "HIGH" },
        },
        blastRadius: { maxActionsPerHour: 10, maxHostsIsolated: 5, twoPerson: ["DISABLE_USER"] },
      });
    case "general":
      return rulebookSchema.parse(base);
  }
}

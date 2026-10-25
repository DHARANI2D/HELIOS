import { z } from "zod";

import type { CategoryKey, ToolDefinition } from "@/lib/integrations/catalog";

// A client's endpoints by operating system. The configurator and the public
// estimator collect it so tool suggestions can check that a product actually
// runs on the client's machines (a macOS-only MDM leaves Windows PCs
// unmanaged). Client-safe and pure.

export const ENDPOINT_TYPES = [
  { key: "windows", label: "Windows PCs", platform: "Windows", kind: "workstation" },
  { key: "macos", label: "Macs", platform: "macOS", kind: "workstation" },
  { key: "linux", label: "Linux desktops", platform: "Linux", kind: "workstation" },
  { key: "windowsServer", label: "Windows servers", platform: "Windows", kind: "server" },
  { key: "linuxServer", label: "Linux servers", platform: "Linux", kind: "server" },
  { key: "ios", label: "iPhones & iPads", platform: "iOS", kind: "mobile" },
  { key: "android", label: "Android devices", platform: "Android", kind: "mobile" },
  { key: "other", label: "Other / unknown OS", platform: null, kind: "workstation" },
] as const;

export type EndpointTypeKey = (typeof ENDPOINT_TYPES)[number]["key"];
type EndpointKind = (typeof ENDPOINT_TYPES)[number]["kind"];

const count = z.number().int().min(0).max(1_000_000).default(0);
export const endpointMixSchema = z.object({
  windows: count,
  macos: count,
  linux: count,
  windowsServer: count,
  linuxServer: count,
  ios: count,
  android: count,
  other: count,
});
export type EndpointMix = z.infer<typeof endpointMixSchema>;

export const EMPTY_MIX: EndpointMix = { windows: 0, macos: 0, linux: 0, windowsServer: 0, linuxServer: 0, ios: 0, android: 0, other: 0 };

const sumOf = (mix: EndpointMix, kind: EndpointKind) => ENDPOINT_TYPES.filter((t) => t.kind === kind).reduce((s, t) => s + mix[t.key], 0);

// Computers are what the managed service bills per endpoint; phones and
// tablets only count for device management.
export const mixWorkstations = (mix: EndpointMix) => sumOf(mix, "workstation");
export const mixServers = (mix: EndpointMix) => sumOf(mix, "server");
export const mixMobile = (mix: EndpointMix) => sumOf(mix, "mobile");

// Inventory OS strings ("Windows Server 2022", "macOS 15", "Ubuntu 24.04")
// to a type. Linux without a desktop hint counts as a server: that is where
// most managed Linux runs.
export function classifyOs(os: string | null | undefined): EndpointTypeKey {
  const s = (os ?? "").toLowerCase();
  if (!s.trim()) return "other";
  if (/windows/.test(s)) return /server/.test(s) ? "windowsServer" : "windows";
  if (/mac ?os|os x|darwin/.test(s)) return "macos";
  if (/ipados|ios\b|iphone|ipad/.test(s)) return "ios";
  if (/android/.test(s)) return "android";
  if (/linux|ubuntu|debian|rhel|red hat|centos|fedora|suse|alma|rocky|amazon linux|oracle linux/.test(s)) {
    return /desktop|workstation|mint|pop!?_os/.test(s) && !/server/.test(s) ? "linux" : "linuxServer";
  }
  return "other";
}

export function mixFromInventory(osList: Array<string | null>): EndpointMix {
  return mixFromCounts(osList.map((os) => ({ os, count: 1 })));
}

// From inventory counts per OS. Endpoints licensed beyond the inventory are
// counted as unknown OS, so the mix never undercounts the contract.
export function mixFromCounts(rows: Array<{ os: string | null; count: number }>, licensed = 0): EndpointMix {
  const mix = { ...EMPTY_MIX };
  for (const r of rows) mix[classifyOs(r.os)] += r.count;
  const counted = mixWorkstations(mix) + mixServers(mix);
  if (licensed > counted) mix.other += licensed - counted;
  return mix;
}

// Which endpoint kinds a tool in each category has to run on. Categories not
// listed (email, identity, SIEM…) protect services, not machines.
const CATEGORY_SCOPE: Partial<Record<CategoryKey, EndpointKind[]>> = {
  edr: ["workstation", "server"],
  epp: ["workstation", "server"],
  vuln: ["workstation", "server"],
  backup: ["workstation", "server"],
  dlp: ["workstation"],
  mdm: ["workstation", "mobile"],
  network: ["workstation", "mobile"],
};

const OS_PLATFORMS = new Set(["Windows", "macOS", "Linux", "iOS", "Android"]);

export interface PlatformFit {
  relevant: number; // endpoints of a known OS the tool has to cover
  supported: number;
  unsupported: Array<{ type: EndpointTypeKey; label: string; count: number }>;
  unknown: number; // endpoints of unknown OS, not checked
  // No endpoint agent (appliance, SaaS): nothing to install, nothing left out.
  agentless: boolean;
  ratio: number; // supported / relevant, 1 when nothing to check
}

export function platformFit(tool: Pick<ToolDefinition, "category" | "platforms">, mix: EndpointMix | null | undefined): PlatformFit | null {
  const scope = CATEGORY_SCOPE[tool.category];
  if (!mix || !scope) return null;
  const types = ENDPOINT_TYPES.filter((t) => scope.includes(t.kind) && t.platform && mix[t.key] > 0);
  const relevant = types.reduce((s, t) => s + mix[t.key], 0);
  const unknown = scope.includes("workstation") ? mix.other : 0;
  const agentless = !tool.platforms.some((p) => OS_PLATFORMS.has(p));
  if (agentless) return { relevant, supported: relevant, unsupported: [], unknown, agentless, ratio: 1 };
  const unsupported = types.filter((t) => !tool.platforms.includes(t.platform!)).map((t) => ({ type: t.key, label: t.label, count: mix[t.key] }));
  const supported = relevant - unsupported.reduce((s, u) => s + u.count, 0);
  return { relevant, supported, unsupported, unknown, agentless, ratio: relevant ? supported / relevant : 1 };
}

export function describeMix(mix: EndpointMix) {
  return ENDPOINT_TYPES.filter((t) => mix[t.key] > 0)
    .map((t) => `${mix[t.key].toLocaleString("en-US")} ${t.label}`)
    .join(", ");
}

import type { PlaybookActionType } from "@prisma/client";

import type { ConnectorField, NativeConnector } from "@/lib/connectors/types";
import { defender } from "@/lib/connectors/vendors/defender";
import { entra } from "@/lib/connectors/vendors/entra";
import { crowdstrike } from "@/lib/connectors/vendors/crowdstrike";
import { sentinelone } from "@/lib/connectors/vendors/sentinelone";
import { okta } from "@/lib/connectors/vendors/okta";
import { cloudflare } from "@/lib/connectors/vendors/cloudflare";
import { exchange } from "@/lib/connectors/vendors/exchange";

// Native response connectors by the catalog tools they serve. A tool without
// one can still act through the signed response webhook (a SOAR or script).

export const CONNECTORS: NativeConnector[] = [defender, entra, crowdstrike, sentinelone, okta, cloudflare, exchange];

export function connectorForTool(toolKey: string): NativeConnector | undefined {
  return CONNECTORS.find((c) => c.tools.includes(toolKey));
}

export function connectorByKey(key: string | undefined | null): NativeConnector | undefined {
  return CONNECTORS.find((c) => c.key === key);
}

// What the setup screens show, safe to hand to the browser.
export interface ConnectorInfo {
  key: string;
  label: string;
  actions: PlaybookActionType[];
  fields: ConnectorField[];
  docs: string;
}

export function connectorInfo(c: NativeConnector): ConnectorInfo {
  return { key: c.key, label: c.label, actions: c.actions, fields: c.fields, docs: c.docs };
}

"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { logAction } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { getSetting, setSetting } from "@/lib/settings";
import { DETECTORS } from "@/lib/siem/engine";

export async function setDetectorEnabledAction(name: string, enabled: boolean) {
  const user = await requirePermission("detections.tune");
  const detector = z.enum(DETECTORS.map((d) => d.name) as [string, ...string[]]).parse(name);
  const disabled = new Set(await getSetting("detection.disabledDetectors"));
  if (enabled) disabled.delete(detector);
  else disabled.add(detector);
  await setSetting("detection.disabledDetectors", [...disabled], user.id);
  await logAction({ actorId: user.id, action: enabled ? "detection.detector_enabled" : "detection.detector_disabled", detail: { detector } });
  revalidatePath("/mitre");
  revalidatePath("/detections");
}

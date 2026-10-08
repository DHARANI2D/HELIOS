"use client";

import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { Save, Loader2 } from "lucide-react";
import { toast } from "sonner";
import type { AiTier, OrganizationStatus } from "@prisma/client";

import { updateOrganizationAction } from "@/app/(app)/admin/organizations/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const AI_TIERS: AiTier[] = ["ESSENTIAL", "PROFESSIONAL", "ENTERPRISE", "SELF_HOSTED"];
const STATUSES: OrganizationStatus[] = ["TRIAL", "ACTIVE", "SUSPENDED"];

export function OrgSettingsForm({
  organizationId,
  aiTier,
  status,
  selfHostedOllamaUrl,
}: {
  organizationId: string;
  aiTier: AiTier;
  status: OrganizationStatus;
  selfHostedOllamaUrl: string | null;
}) {
  const [nextAiTier, setNextAiTier] = React.useState(aiTier);
  const [nextStatus, setNextStatus] = React.useState(status);
  const [ollamaUrl, setOllamaUrl] = React.useState(selfHostedOllamaUrl ?? "");

  const mutation = useMutation({
    mutationFn: () =>
      updateOrganizationAction(organizationId, {
        aiTier: nextAiTier,
        status: nextStatus,
        selfHostedOllamaUrl: nextAiTier === "SELF_HOSTED" ? ollamaUrl.trim() || null : null,
      }),
    onSuccess: () => toast.success("Settings saved"),
    onError: () => toast.error("Failed to save settings"),
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        mutation.mutate();
      }}
      className="flex flex-col gap-3"
    >
      <div className="flex flex-col gap-1.5">
        <Label>AI tier</Label>
        <Select value={nextAiTier} onValueChange={(v) => setNextAiTier(v as AiTier)}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {AI_TIERS.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {nextAiTier === "SELF_HOSTED" && (
        <div className="flex flex-col gap-1.5">
          <Label>Self-hosted Ollama URL</Label>
          <Input
            value={ollamaUrl}
            onChange={(e) => setOllamaUrl(e.target.value)}
            placeholder="http://customer-host:11434"
          />
        </div>
      )}

      <div className="flex flex-col gap-1.5">
        <Label>Status</Label>
        <Select value={nextStatus} onValueChange={(v) => setNextStatus(v as OrganizationStatus)}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Button type="submit" disabled={mutation.isPending} className="self-start">
        {mutation.isPending ? <Loader2 className="animate-spin" /> : <Save />}
        Save
      </Button>
    </form>
  );
}

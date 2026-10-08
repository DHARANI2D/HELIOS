"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Loader2, Copy } from "lucide-react";
import { toast } from "sonner";
import type { IntegrationCategory } from "@prisma/client";

import { createIntegrationAction } from "@/app/(app)/integrations/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const CATEGORIES: IntegrationCategory[] = ["SIEM", "EDR", "CLOUD", "IDENTITY", "EMAIL", "OTHER"];

export function CreateIntegrationDialog() {
  const [open, setOpen] = React.useState(false);
  const [vendorLabel, setVendorLabel] = React.useState("");
  const [category, setCategory] = React.useState<IntegrationCategory>("SIEM");
  const [created, setCreated] = React.useState<{ id: string; webhookSecret: string } | null>(null);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => createIntegrationAction(vendorLabel.trim(), category),
    onSuccess: (integration) => {
      setCreated({ id: integration.id, webhookSecret: integration.webhookSecret });
      queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: () => toast.error("Failed to create integration"),
  });

  function reset() {
    setVendorLabel("");
    setCategory("SIEM");
    setCreated(null);
  }

  const webhookUrl = created
    ? `${typeof window !== "undefined" ? window.location.origin : ""}/api/integrations/${created.id}/ingest`
    : "";

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <Plus /> Connect a tool
        </Button>
      </DialogTrigger>
      <DialogContent>
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle>Integration created</DialogTitle>
              <DialogDescription>
                Point your tool&apos;s webhook at this URL with this secret as a Bearer token — it
                won&apos;t be shown again.
              </DialogDescription>
            </DialogHeader>
            <div className="flex flex-col gap-2">
              <Label>Webhook URL</Label>
              <div className="flex items-center gap-2 rounded-md border bg-muted/40 p-2 font-mono text-xs break-all">
                {webhookUrl}
                <Button
                  variant="ghost"
                  size="icon"
                  className="ml-auto shrink-0"
                  onClick={() => {
                    navigator.clipboard.writeText(webhookUrl);
                    toast.success("Copied");
                  }}
                >
                  <Copy className="size-4" />
                </Button>
              </div>
              <Label>Secret (Bearer token)</Label>
              <div className="flex items-center gap-2 rounded-md border bg-muted/40 p-2 font-mono text-xs break-all">
                {created.webhookSecret}
                <Button
                  variant="ghost"
                  size="icon"
                  className="ml-auto shrink-0"
                  onClick={() => {
                    navigator.clipboard.writeText(created.webhookSecret);
                    toast.success("Copied");
                  }}
                >
                  <Copy className="size-4" />
                </Button>
              </div>
            </div>
            <DialogFooter>
              <Button onClick={() => setOpen(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Connect a tool</DialogTitle>
              <DialogDescription>
                Generates a webhook URL + secret — point your SIEM/EDR/cloud tool&apos;s outbound
                webhook at it.
              </DialogDescription>
            </DialogHeader>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!vendorLabel.trim()) {
                  toast.error("Give it a name");
                  return;
                }
                mutation.mutate();
              }}
              className="flex flex-col gap-3"
            >
              <div className="flex flex-col gap-1.5">
                <Label>Name</Label>
                <Input
                  value={vendorLabel}
                  onChange={(e) => setVendorLabel(e.target.value)}
                  placeholder="e.g. CrowdStrike Falcon, Splunk, Wazuh"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>Category</Label>
                <Select value={category} onValueChange={(v) => setCategory(v as IntegrationCategory)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CATEGORIES.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={mutation.isPending}>
                  {mutation.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
                  Create
                </Button>
              </DialogFooter>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

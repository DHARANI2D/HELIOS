"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Loader2, Copy } from "lucide-react";
import { toast } from "sonner";
import type { AiTier } from "@prisma/client";

import { createOrganizationAction } from "@/app/(app)/admin/organizations/actions";
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

const AI_TIERS: AiTier[] = ["ESSENTIAL", "PROFESSIONAL", "ENTERPRISE", "SELF_HOSTED"];

export function CreateOrganizationDialog() {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [adminName, setAdminName] = React.useState("");
  const [adminEmail, setAdminEmail] = React.useState("");
  const [aiTier, setAiTier] = React.useState<AiTier>("PROFESSIONAL");
  const [created, setCreated] = React.useState<{ tempPassword: string } | null>(null);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      createOrganizationAction({
        name: name.trim(),
        aiTier,
        orgAdminEmail: adminEmail.trim(),
        orgAdminName: adminName.trim(),
      }),
    onSuccess: (result) => {
      setCreated({ tempPassword: result.tempPassword });
      queryClient.invalidateQueries({ queryKey: ["admin-organizations"] });
    },
    onError: () => toast.error("Failed to create organization"),
  });

  function reset() {
    setName("");
    setAdminName("");
    setAdminEmail("");
    setAiTier("PROFESSIONAL");
    setCreated(null);
  }

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
          <Plus /> New organization
        </Button>
      </DialogTrigger>
      <DialogContent>
        {created ? (
          <>
            <DialogHeader>
              <DialogTitle>Organization created</DialogTitle>
              <DialogDescription>
                Hand this temporary password to the customer out of band — it won&apos;t be shown again.
              </DialogDescription>
            </DialogHeader>
            <div className="flex items-center gap-2 rounded-md border bg-muted/40 p-3 font-mono text-sm">
              {created.tempPassword}
              <Button
                variant="ghost"
                size="icon"
                className="ml-auto"
                onClick={() => {
                  navigator.clipboard.writeText(created.tempPassword);
                  toast.success("Copied");
                }}
              >
                <Copy className="size-4" />
              </Button>
            </div>
            <DialogFooter>
              <Button onClick={() => setOpen(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Create organization</DialogTitle>
              <DialogDescription>
                Provisions a new tenant and its first org admin user. No self-service signup exists —
                this is the only way a customer gets onboarded.
              </DialogDescription>
            </DialogHeader>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!name.trim() || !adminEmail.trim() || !adminName.trim()) {
                  toast.error("All fields are required");
                  return;
                }
                mutation.mutate();
              }}
              className="flex flex-col gap-3"
            >
              <div className="flex flex-col gap-1.5">
                <Label>Organization name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>AI tier</Label>
                <Select value={aiTier} onValueChange={(v) => setAiTier(v as AiTier)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {AI_TIERS.map((tier) => (
                      <SelectItem key={tier} value={tier}>
                        {tier}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>First admin&apos;s name</Label>
                <Input value={adminName} onChange={(e) => setAdminName(e.target.value)} placeholder="Jane Doe" />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label>First admin&apos;s email</Label>
                <Input
                  type="email"
                  value={adminEmail}
                  onChange={(e) => setAdminEmail(e.target.value)}
                  placeholder="jane@acme.com"
                />
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

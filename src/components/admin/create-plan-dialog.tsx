"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Loader2 } from "lucide-react";
import { toast } from "sonner";
import type { AiTier, ServiceType } from "@prisma/client";

import { createPlanAction } from "@/app/(app)/admin/plans/actions";
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

const SERVICE_TYPES: ServiceType[] = [
  "ENDPOINT_SECURITY",
  "CLOUD_SECURITY",
  "NETWORK_SECURITY",
  "EMAIL_SECURITY",
  "AGENT_GOVERNANCE",
  "PENETRATION_TESTING",
];
const AI_TIERS: AiTier[] = ["ESSENTIAL", "PROFESSIONAL", "ENTERPRISE", "SELF_HOSTED"];

export function CreatePlanDialog() {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [serviceType, setServiceType] = React.useState<ServiceType>("ENDPOINT_SECURITY");
  const [aiTier, setAiTier] = React.useState<AiTier>("PROFESSIONAL");
  const [price, setPrice] = React.useState("");
  const [description, setDescription] = React.useState("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      createPlanAction({
        name: name.trim(),
        serviceType,
        aiTier,
        priceMonthly: Number(price),
        description: description.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Plan created");
      setOpen(false);
      setName("");
      setPrice("");
      setDescription("");
      queryClient.invalidateQueries({ queryKey: ["admin-plans"] });
    },
    onError: () => toast.error("Failed to create plan"),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus /> New plan
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create plan</DialogTitle>
          <DialogDescription>
            One service × AI tier price point customers can subscribe to.
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!name.trim() || !price || Number(price) <= 0) {
              toast.error("Name and a positive price are required");
              return;
            }
            mutation.mutate();
          }}
          className="flex flex-col gap-3"
        >
          <div className="flex flex-col gap-1.5">
            <Label>Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Endpoint Security — Professional"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label>Service</Label>
              <Select value={serviceType} onValueChange={(v) => setServiceType(v as ServiceType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SERVICE_TYPES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s.replaceAll("_", " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>AI tier</Label>
              <Select value={aiTier} onValueChange={(v) => setAiTier(v as AiTier)}>
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
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Price / month (USD)</Label>
            <Input type="number" min="0" step="0.01" value={price} onChange={(e) => setPrice(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Description</Label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <DialogFooter>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

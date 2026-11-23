"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { BrainCircuit, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { registerSystemAction } from "@/app/(app)/ai-security/actions";
import { unwrap } from "@/lib/action-result";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

export function RegisterSystemForm({ tenants, isClient, kinds, dataClasses, defaultTenantId }: { tenants: Array<{ id: string; name: string }>; isClient: boolean; kinds: Record<string, string>; dataClasses: Record<string, string>; defaultTenantId?: string | null }) {
  const router = useRouter();
  const [open, setOpen] = React.useState(false);
  const [form, setForm] = React.useState({ tenantId: defaultTenantId ?? tenants[0]?.id ?? "", name: "", kind: "CHATBOT", description: "", owner: "", dataClasses: [] as string[], endpoint: "" });
  const set = (k: keyof typeof form, v: unknown) => setForm((f) => ({ ...f, [k]: v }));
  const submit = useMutation({
    mutationFn: () => unwrap(registerSystemAction({ ...form, kind: form.kind as "CHATBOT" })),
    onSuccess: ({ id }) => {
      toast.success("Registered. Next: issue its key and connect the application.");
      setOpen(false);
      router.push(`/ai-security/${id}`);
    },
    onError: (err: Error) => toast.error(err.message),
  });
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button><BrainCircuit /> Register an AI system</Button>
      </DialogTrigger>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Register an AI system</DialogTitle>
          <DialogDescription>A chatbot, an agent, a search (RAG) application or a model API {isClient ? "you run" : "the client runs"}. It starts with HELIOS&apos;s baseline guard policy plus the packs its data calls for; you can change everything afterwards.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          {!isClient && (
            <div className="grid gap-1.5">
              <Label htmlFor="ai-tenant">Client</Label>
              <NativeSelect id="ai-tenant" value={form.tenantId} onChange={(e) => set("tenantId", e.target.value)}>
                {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
              </NativeSelect>
            </div>
          )}
          <div className="grid gap-1.5">
            <Label htmlFor="ai-name">Name</Label>
            <Input id="ai-name" value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Patient help chatbot" maxLength={120} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ai-kind">What it is</Label>
            <NativeSelect id="ai-kind" value={form.kind} onChange={(e) => set("kind", e.target.value)}>
              {Object.entries(kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </NativeSelect>
          </div>
          <div className="grid gap-1.5">
            <Label>The data it handles</Label>
            <div className="grid grid-cols-2 gap-1">
              {Object.entries(dataClasses).map(([k, v]) => (
                <label key={k} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={form.dataClasses.includes(k)} onChange={(e) => set("dataClasses", e.target.checked ? [...form.dataClasses, k] : form.dataClasses.filter((d) => d !== k))} />
                  {v}
                </label>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">Personal data adds the privacy pack, health records the healthcare pack, card data the finance pack.</p>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ai-desc">What it does</Label>
            <Textarea id="ai-desc" value={form.description} onChange={(e) => set("description", e.target.value)} rows={2} placeholder="Answers patients' questions about appointments and visiting hours" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="ai-owner">Owner</Label>
              <Input id="ai-owner" value={form.owner} onChange={(e) => set("owner", e.target.value)} placeholder="Digital team" />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ai-endpoint">Chat endpoint (optional)</Label>
              <Input id="ai-endpoint" value={form.endpoint} onChange={(e) => set("endpoint", e.target.value)} placeholder="https://bot.example.com/v1/chat/completions" />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">The chat endpoint is what the AI red team talks to in a security test. Leave it empty if you only want the runtime guard.</p>
        </div>
        <DialogFooter>
          <Button onClick={() => submit.mutate()} disabled={submit.isPending || !form.name.trim() || (!isClient && !form.tenantId)}>
            {submit.isPending && <Loader2 className="animate-spin" />} Register
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

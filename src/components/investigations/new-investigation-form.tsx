"use client";

import * as React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, Loader2 } from "lucide-react";
import { toast } from "sonner";

import {
  createInvestigationAction,
  listLinkableCasesAction,
} from "@/app/(app)/investigations/actions";
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
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function NewInvestigationForm() {
  const [title, setTitle] = React.useState("");
  const [details, setDetails] = React.useState("");
  const [linkedCaseId, setLinkedCaseId] = React.useState<string>("none");
  const queryClient = useQueryClient();

  const { data: linkableCases } = useQuery({
    queryKey: ["linkable-cases"],
    queryFn: () => listLinkableCasesAction(),
  });

  const mutation = useMutation({
    mutationFn: () =>
      createInvestigationAction(title.trim(), details.trim(), linkedCaseId === "none" ? undefined : linkedCaseId),
    onSuccess: () => {
      toast.success("Investigation swarm completed");
      setTitle("");
      setDetails("");
      setLinkedCaseId("none");
      queryClient.invalidateQueries({ queryKey: ["investigations"] });
    },
    onError: () => toast.error("Investigation failed"),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">New investigation</CardTitle>
        <CardDescription>
          Triage → RCA → adversarial QA → report, optionally grounded in an
          existing alert&apos;s ingested telemetry
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!title.trim() || !details.trim()) {
              toast.error("Title and details are required");
              return;
            }
            mutation.mutate();
          }}
          className="flex flex-col gap-3"
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="inv-title">Alert title</Label>
            <Input
              id="inv-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Encoded PowerShell execution on ws-14"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="inv-details">Alert details</Label>
            <textarea
              id="inv-details"
              value={details}
              onChange={(e) => setDetails(e.target.value)}
              rows={3}
              className="border-input dark:bg-input/30 rounded-md border bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
              placeholder="Paste the alert description or raw context here…"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Ground in an existing alert (optional)</Label>
            <Select value={linkedCaseId} onValueChange={setLinkedCaseId}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None — freeform investigation</SelectItem>
                {linkableCases?.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    [{c.severity}] {c.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button type="submit" disabled={mutation.isPending} className="self-start">
            {mutation.isPending ? <Loader2 className="animate-spin" /> : <Search />}
            Run investigation swarm
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

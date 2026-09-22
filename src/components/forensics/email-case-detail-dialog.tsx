"use client";

import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, ShieldAlert, Play } from "lucide-react";
import { toast } from "sonner";

import { getEmailCaseAction, detonateUrlAction } from "@/app/(app)/forensics/actions";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SEVERITY_LABEL, SEVERITY_BADGE_VARIANT } from "@/lib/severity";
import type { AttachmentAnalysis } from "@/lib/forensics/attachments";
import type { AuthResults } from "@/lib/forensics/headers";

interface Props {
  caseId: string | null;
  onClose: () => void;
}

interface CaseMetadata {
  from?: string;
  to?: string;
  headerScore?: number;
  bodyScore?: number;
  attachmentScore?: number;
  urls?: string[];
  suspiciousDomains?: string[];
  authResults?: AuthResults;
  attachments?: AttachmentAnalysis[];
}

export function EmailCaseDetailDialog({ caseId, onClose }: Props) {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["email-case-detail", caseId],
    queryFn: () => getEmailCaseAction(caseId!),
    enabled: !!caseId,
  });

  const [detonatingUrl, setDetonatingUrl] = React.useState<string | null>(null);

  const detonate = useMutation({
    mutationFn: (url: string) => detonateUrlAction(url, caseId!),
    onMutate: (url) => setDetonatingUrl(url),
    onSuccess: (result) => {
      toast[result.error ? "error" : "success"](
        result.error ? `Detonation failed: ${result.error}` : `Detonation scored ${result.score}`,
      );
      queryClient.invalidateQueries({ queryKey: ["email-case-detail", caseId] });
    },
    onSettled: () => setDetonatingUrl(null),
  });

  const metadata = (data?.metadata ?? {}) as CaseMetadata;

  return (
    <Dialog open={!!caseId} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{data?.title ?? "Email analysis"}</DialogTitle>
          <DialogDescription>
            From: {metadata.from} → {metadata.to}
          </DialogDescription>
        </DialogHeader>

        {isLoading && (
          <div className="flex justify-center py-10">
            <Loader2 className="animate-spin" />
          </div>
        )}

        {data && (
          <div className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={SEVERITY_BADGE_VARIANT[data.severity]}>{SEVERITY_LABEL[data.severity]}</Badge>
              <Badge variant="outline" className="capitalize">
                {data.verdict}
              </Badge>
              <Badge variant="secondary">Risk {Math.round(data.riskScore ?? 0)}</Badge>
            </div>

            <Tabs defaultValue="headers">
              <TabsList>
                <TabsTrigger value="headers">Headers</TabsTrigger>
                <TabsTrigger value="body">Body &amp; URLs</TabsTrigger>
                <TabsTrigger value="attachments">Attachments</TabsTrigger>
              </TabsList>

              <TabsContent value="headers" className="flex flex-col gap-2 text-xs">
                {metadata.authResults && (
                  <div className="grid grid-cols-3 gap-2">
                    {(["spf", "dkim", "dmarc"] as const).map((k) => (
                      <div key={k} className="rounded-md border p-2">
                        <p className="font-medium uppercase">{k}</p>
                        <p className="text-muted-foreground">{metadata.authResults![k].status}</p>
                      </div>
                    ))}
                  </div>
                )}
                <ul className="space-y-1">
                  {data.detections
                    .filter((d) => d.source === "EMAIL_HEADER_AUTH")
                    .flatMap((d) => (d.evidence as { reasons?: string[] })?.reasons ?? [])
                    .map((r, i) => (
                      <li key={i} className="rounded-md border p-2">
                        {r}
                      </li>
                    ))}
                </ul>
              </TabsContent>

              <TabsContent value="body" className="flex flex-col gap-3 text-xs">
                {metadata.urls?.length ? (
                  <ul className="space-y-1.5">
                    {metadata.urls.map((url) => (
                      <li key={url} className="flex items-center justify-between gap-2 rounded-md border p-2">
                        <span className="truncate">{url}</span>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={detonatingUrl === url}
                          onClick={() => detonate.mutate(url)}
                        >
                          {detonatingUrl === url ? <Loader2 className="animate-spin" /> : <Play />}
                          Detonate
                        </Button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-muted-foreground">No URLs found in the body.</p>
                )}

                {data.detections
                  .filter((d) => d.source === "EMAIL_SANDBOX_DETONATION")
                  .map((d) => (
                    <div key={d.id} className="rounded-md border p-2">
                      <p className="font-medium">{d.title}</p>
                      <p className="text-muted-foreground">Severity: {d.severity}</p>
                    </div>
                  ))}
              </TabsContent>

              <TabsContent value="attachments" className="flex flex-col gap-2 text-xs">
                {metadata.attachments?.length ? (
                  metadata.attachments.map((a) => (
                    <div key={a.filename} className="rounded-md border p-2">
                      <div className="flex items-center justify-between">
                        <p className="font-medium">{a.filename}</p>
                        {a.score > 0 && (
                          <Badge variant="destructive" className="gap-1">
                            <ShieldAlert className="size-3" />
                            {a.score}
                          </Badge>
                        )}
                      </div>
                      <p className="text-muted-foreground">
                        {a.contentType} · {a.size}B · entropy {a.entropy.toFixed(2)}
                      </p>
                      {a.reasons.length > 0 && (
                        <ul className="mt-1 list-inside list-disc">
                          {a.reasons.map((r, i) => (
                            <li key={i}>{r}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))
                ) : (
                  <p className="text-muted-foreground">No attachments.</p>
                )}
              </TabsContent>
            </Tabs>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

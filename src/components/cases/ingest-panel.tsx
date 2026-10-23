"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Upload } from "lucide-react";
import { toast } from "sonner";

import { ingestLogsAction } from "@/app/(app)/cases/actions";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";

const EXAMPLE = `[
  {"user": "jane.roe", "source_ip": "203.0.113.7", "result": "FAILED", "geo_location": "Brazil"},
  {"user": "jane.roe", "source_ip": "203.0.113.7", "result": "SUCCESS", "geo_location": "Brazil"}
]`;

export function IngestPanel() {
  const router = useRouter();
  const [source, setSource] = React.useState("auth");
  const [text, setText] = React.useState("");

  const ingest = useMutation({
    mutationFn: () => ingestLogsAction(source, text),
    onSuccess: (s) => {
      toast.success(`Ingested ${s.eventsIngested} events → ${s.newDetections} new detections, ${s.casesCreated} new / ${s.casesUpdated} updated cases`);
      setText("");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Ingest failed"),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Ingest telemetry</CardTitle>
        <CardDescription>
          Paste a JSON array, a single object, or JSON Lines. Items shaped <code className="text-[11px]">{"{source, data}"}</code> may mix sources.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={EXAMPLE}
          className="min-h-32 font-mono text-xs"
        />
        <div className="flex items-center gap-2">
          <NativeSelect value={source} onChange={(e) => setSource(e.target.value)} aria-label="Default source">
            <option value="auth">auth</option>
            <option value="endpoint">endpoint</option>
            <option value="network">network</option>
            <option value="cloud">cloud</option>
          </NativeSelect>
          <Button onClick={() => ingest.mutate()} disabled={ingest.isPending || !text.trim()}>
            {ingest.isPending ? <Loader2 className="animate-spin" /> : <Upload />}
            Ingest
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

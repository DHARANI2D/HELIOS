"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Search, Loader2 } from "lucide-react";
import { toast } from "sonner";
import type { IndicatorType } from "@prisma/client";

import { lookupIndicatorAction } from "@/app/(app)/threat-intel/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const TYPE_OPTIONS: { value: IndicatorType; label: string; placeholder: string }[] = [
  { value: "IP", label: "IP address", placeholder: "185.220.101.5" },
  { value: "DOMAIN", label: "Domain", placeholder: "update-service.net" },
  { value: "URL", label: "URL", placeholder: "https://example.com/path" },
  { value: "FILE_HASH", label: "File hash", placeholder: "sha256_abc..." },
  { value: "EMAIL_ADDRESS", label: "Email address", placeholder: "user@example.com" },
];

export function LookupForm() {
  const [type, setType] = React.useState<IndicatorType>("IP");
  const [value, setValue] = React.useState("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: () => lookupIndicatorAction(type, value.trim()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["threat-indicators"] });
    },
    onError: () => toast.error("Lookup failed"),
  });

  const selected = TYPE_OPTIONS.find((o) => o.value === type)!;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">IOC lookup</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!value.trim()) return;
            mutation.mutate();
          }}
          className="flex flex-col gap-2 sm:flex-row"
        >
          <Select value={type} onValueChange={(v) => setType(v as IndicatorType)}>
            <SelectTrigger className="sm:w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TYPE_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={selected.placeholder}
            className="flex-1"
          />
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? <Loader2 className="animate-spin" /> : <Search />}
            Look up
          </Button>
        </form>

        {mutation.data && (
          <div className="rounded-md border p-3 text-sm">
            <div className="mb-1 flex items-center gap-2">
              <span className="font-medium">{mutation.data.value}</span>
              <Badge
                variant={
                  (mutation.data.maliciousScore ?? 0) > 0.5 ? "destructive" : "secondary"
                }
              >
                {Math.round((mutation.data.maliciousScore ?? 0) * 100)}% malicious
              </Badge>
            </div>
            <pre className="overflow-x-auto text-xs text-muted-foreground">
              {JSON.stringify(mutation.data.providerData, null, 2)}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

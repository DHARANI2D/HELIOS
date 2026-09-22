"use client";

import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Upload, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { analyzeEmailAction } from "@/app/(app)/forensics/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function UploadPanel() {
  const [file, setFile] = React.useState<File | null>(null);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async () => {
      const formData = new FormData();
      formData.append("file", file!);
      return analyzeEmailAction(formData);
    },
    onSuccess: () => {
      toast.success("Email analyzed");
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
      queryClient.invalidateQueries({ queryKey: ["email-cases"] });
    },
    onError: (err) => toast.error(`Analysis failed: ${err instanceof Error ? err.message : String(err)}`),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Analyze an email</CardTitle>
        <CardDescription>Upload a .eml file for header, body, and attachment forensics</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!file) {
              toast.error("Choose a .eml file first");
              return;
            }
            mutation.mutate();
          }}
          className="flex flex-col gap-3 sm:flex-row sm:items-center"
        >
          <Input
            ref={inputRef}
            type="file"
            accept=".eml,message/rfc822"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="max-w-sm"
          />
          <Button type="submit" disabled={mutation.isPending || !file}>
            {mutation.isPending ? <Loader2 className="animate-spin" /> : <Upload />}
            Analyze
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

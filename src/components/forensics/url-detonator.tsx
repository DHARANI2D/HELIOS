"use client";

import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { Bomb, Loader2 } from "lucide-react";

import { detonateUrlAction } from "@/app/(app)/forensics/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DetonationView } from "@/components/forensics/detonation-view";

export function UrlDetonator() {
  const [url, setUrl] = React.useState("");
  const detonate = useMutation({ mutationFn: () => detonateUrlAction(url) });

  return (
    <div className="flex flex-col gap-3">
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (url.trim()) detonate.mutate();
        }}
      >
        <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://suspicious.example/login" className="font-mono text-sm" />
        <Button type="submit" disabled={detonate.isPending || !url.trim()}>
          {detonate.isPending ? <Loader2 className="animate-spin" /> : <Bomb />}
          Detonate
        </Button>
      </form>
      {detonate.isError && <p className="text-sm text-destructive">{detonate.error instanceof Error ? detonate.error.message : "Failed"}</p>}
      {detonate.data && <DetonationView result={detonate.data} />}
    </div>
  );
}

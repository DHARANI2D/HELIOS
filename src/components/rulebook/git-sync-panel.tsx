"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { GitBranch, Loader2, RefreshCw, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { removeGitSyncAction, saveGitSyncAction, syncRulebookNowAction } from "@/app/(app)/rulebook/actions";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { unwrap } from "@/lib/action-result";

export interface GitSyncView {
  provider: string;
  repo: string;
  host: string | null;
  branch: string;
  path: string;
  enabled: boolean;
  tokenSet: boolean;
  lastCheckedAt: string | null;
  lastVersion: number | null;
  lastError: string | null;
}

const onError = (e: Error) => toast.error(e.message);

export function GitSyncPanel({ tenantId, value, canEdit }: { tenantId: string; value: GitSyncView | null; canEdit: boolean }) {
  const router = useRouter();
  const [provider, setProvider] = React.useState(value?.provider ?? "github");
  const [repo, setRepo] = React.useState(value?.repo ?? "");
  const [host, setHost] = React.useState(value?.host ?? "");
  const [branch, setBranch] = React.useState(value?.branch ?? "main");
  const [path, setPath] = React.useState(value?.path ?? "helios/rulebook.yaml");
  const [token, setToken] = React.useState("");
  const [enabled, setEnabled] = React.useState(value?.enabled ?? true);
  const save = useMutation({ mutationFn: () => unwrap(saveGitSyncAction(tenantId, { provider: provider as "github", repo, host, branch, path, token, enabled })), onSuccess: () => { toast.success("Git sync saved"); setToken(""); router.refresh(); }, onError });
  const sync = useMutation({ mutationFn: () => unwrap(syncRulebookNowAction(tenantId)), onSuccess: (r) => { (r.status === "error" ? toast.error : toast.success)(r.message); router.refresh(); }, onError });
  const remove = useMutation({ mutationFn: () => unwrap(removeGitSyncAction(tenantId)), onSuccess: () => { toast.success("Git sync removed"); router.refresh(); }, onError });
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><GitBranch className="size-4" /> Keep it in Git</CardTitle>
        <CardDescription>
          HELIOS reads the rulebook YAML from the client&apos;s repository every hour. A change becomes a draft naming the commit&apos;s file hash; it applies only once someone signs it here, so a commit alone never changes what HELIOS may do.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {value && (
          <p className="text-xs">
            {value.lastCheckedAt ? `Last read ${new Date(value.lastCheckedAt).toISOString().slice(0, 16).replace("T", " ")} UTC` : "Not read yet"}
            {value.lastVersion ? ` · last imported as draft v${value.lastVersion}` : ""}
            {value.lastError && <span className="block text-destructive">{value.lastError}</span>}
          </p>
        )}
        {canEdit && (
          <>
            <div className="grid gap-2 sm:grid-cols-[9rem_1fr_10rem]">
              <div className="grid gap-1">
                <Label htmlFor="git-provider" className="text-xs">Where</Label>
                <NativeSelect id="git-provider" className="h-8 text-xs" value={provider} onChange={(e) => setProvider(e.target.value)}>
                  <option value="github">GitHub</option>
                  <option value="gitlab">GitLab</option>
                  <option value="url">Another https URL</option>
                </NativeSelect>
              </div>
              <div className="grid gap-1">
                <Label htmlFor="git-repo" className="text-xs">{provider === "github" ? "Repository (owner/name)" : provider === "gitlab" ? "Project (group/project)" : "The raw file's https address"}</Label>
                <Input id="git-repo" className="h-8 font-mono text-xs" value={repo} onChange={(e) => setRepo(e.target.value)} />
              </div>
              {provider === "gitlab" ? (
                <div className="grid gap-1"><Label htmlFor="git-host" className="text-xs">Self-managed host</Label><Input id="git-host" className="h-8 text-xs" placeholder="gitlab.com" value={host} onChange={(e) => setHost(e.target.value)} /></div>
              ) : <span />}
            </div>
            {provider !== "url" && (
              <div className="grid gap-2 sm:grid-cols-[10rem_1fr]">
                <div className="grid gap-1"><Label htmlFor="git-branch" className="text-xs">Branch</Label><Input id="git-branch" className="h-8 font-mono text-xs" value={branch} onChange={(e) => setBranch(e.target.value)} /></div>
                <div className="grid gap-1"><Label htmlFor="git-path" className="text-xs">File</Label><Input id="git-path" className="h-8 font-mono text-xs" value={path} onChange={(e) => setPath(e.target.value)} /></div>
              </div>
            )}
            <div className="grid gap-2 sm:grid-cols-[1fr_auto] sm:items-end">
              <div className="grid gap-1">
                <Label htmlFor="git-token" className="text-xs">Read-only token {value?.tokenSet ? "(one is stored; blank keeps it, - removes it)" : "(blank for a public repository)"}</Label>
                <Input id="git-token" type="password" autoComplete="off" className="h-8 text-xs" value={token} onChange={(e) => setToken(e.target.value)} />
              </div>
              <label className="flex items-center gap-2 pb-1.5 text-xs"><Switch checked={enabled} onCheckedChange={setEnabled} /> Read every hour</label>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" disabled={save.isPending || repo.trim().length < 3} onClick={() => save.mutate()}>{save.isPending ? <Loader2 className="animate-spin" /> : <Save />} Save</Button>
              {value && <Button size="sm" variant="outline" disabled={sync.isPending} onClick={() => sync.mutate()}>{sync.isPending ? <Loader2 className="animate-spin" /> : <RefreshCw />} Read now</Button>}
              {value && <Button size="sm" variant="ghost" disabled={remove.isPending} onClick={() => remove.mutate()}><Trash2 /> Stop syncing</Button>}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

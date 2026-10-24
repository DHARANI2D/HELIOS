"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { AtSign, Bot, Eye, EyeOff, Loader2, Lock, Send, Share2, TrendingUp, UserRound } from "lucide-react";
import { toast } from "sonner";

import { addCommentAction, publishReportAction } from "@/app/(app)/cases/actions";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Markdown } from "@/components/shared/markdown";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export interface CommentView {
  id: string;
  authorName: string;
  authorId: string | null;
  kind: string;
  body: string;
  internal: boolean;
  createdAt: string;
}

interface Mentionable {
  id: string;
  name: string;
  role: string;
  client?: boolean;
}

interface DiscussionProps {
  caseId: string;
  comments: CommentView[];
  people: Mentionable[];
  canComment: boolean;
  canPublish: boolean;
  isClient: boolean;
  now: string;
}

const KIND_ICON: Record<string, typeof Bot> = { ai: Bot, ai_report: Bot, escalation: TrendingUp, share: Share2, report: Share2 };

export function Discussion({ caseId, comments, people, canComment, canPublish, isClient, now }: DiscussionProps) {
  const router = useRouter();
  const [body, setBody] = React.useState("");
  const [internal, setInternal] = React.useState(!isClient);
  const [mentions, setMentions] = React.useState<Mentionable[]>([]);
  const nowDate = React.useMemo(() => new Date(now), [now]);

  const post = useMutation({
    mutationFn: () =>
      addCommentAction(caseId, {
        body,
        internal,
        mentions: mentions.filter((m) => body.includes(`@${m.name}`)).map((m) => m.id),
      }),
    onSuccess: () => {
      setBody("");
      setMentions([]);
      toast.success(internal ? "Comment posted (internal)" : "Comment posted — visible to the client");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Could not post comment"),
  });
  const publish = useMutation({
    mutationFn: (commentId: string) => publishReportAction(caseId, commentId),
    onSuccess: () => {
      toast.success("Report published to the client");
      router.refresh();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Publish failed"),
  });

  // Client-visible comments can only mention people the client can see.
  const mentionable = internal ? people.filter((p) => !p.client) : people;

  function mention(person: Mentionable) {
    setBody((b) => `${b}${b && !b.endsWith(" ") ? " " : ""}@${person.name} `);
    setMentions((m) => (m.some((x) => x.id === person.id) ? m : [...m, person]));
  }

  return (
    <div className="flex flex-col gap-4">
      {comments.length === 0 ? (
        <p className="text-sm text-muted-foreground">No discussion yet. Mention a teammate to pull them in.</p>
      ) : (
        <ol className="flex flex-col gap-3">
          {comments.map((c) => {
            const Icon = KIND_ICON[c.kind] ?? UserRound;
            const ai = c.kind === "ai" || c.kind === "ai_report";
            return (
              <li key={c.id} className={cn("rounded-lg border p-3", ai && "border-chart-4/30 bg-chart-4/5", !c.internal && "border-info/40")}>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className={cn("flex size-6 items-center justify-center rounded-full bg-muted", ai && "bg-chart-4/15 text-chart-4")}>
                    <Icon className="size-3.5" />
                  </span>
                  <span className="font-medium text-foreground">{c.authorName}</span>
                  <span className="text-muted-foreground" title={c.createdAt}>{formatRelative(new Date(c.createdAt), nowDate)}</span>
                  {c.kind === "ai_report" && <Badge variant="ai">Draft report</Badge>}
                  {!isClient &&
                    (c.internal ? (
                      <Badge variant="soft"><Lock /> Internal</Badge>
                    ) : (
                      <Badge variant="info"><Eye /> Client-visible</Badge>
                    ))}
                </div>
                <div className="mt-2 text-sm">
                  <Markdown>{c.body}</Markdown>
                </div>
                {c.kind === "ai_report" && canPublish && (
                  <div className="mt-2">
                    <Button size="sm" variant="outline" onClick={() => publish.mutate(c.id)} disabled={publish.isPending}>
                      {publish.isPending ? <Loader2 className="animate-spin" /> : <Share2 />}
                      Publish to client
                    </Button>
                  </div>
                )}
              </li>
            );
          })}
        </ol>
      )}

      {canComment && (
        <div className="flex flex-col gap-2 rounded-lg border bg-muted/30 p-3">
          <Textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder={isClient ? "Reply to your SOC team…" : "Write an update, @mention a teammate…"}
            className="min-h-20 bg-background text-sm"
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === "Enter" && body.trim()) post.mutate();
            }}
          />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {mentionable.length > 0 && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button size="sm" variant="ghost" type="button">
                      <AtSign /> Mention
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="max-h-72 w-64 overflow-y-auto">
                    <DropdownMenuLabel className="text-xs">Notify someone</DropdownMenuLabel>
                    {mentionable.map((p) => (
                      <DropdownMenuItem key={p.id} onSelect={() => mention(p)}>
                        <span className="truncate">{p.name}</span>
                        <span className="ml-auto truncate text-[11px] text-muted-foreground">{p.role}</span>
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
              {!isClient && (
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Switch checked={!internal} onCheckedChange={(v) => setInternal(!v)} />
                  {internal ? (
                    <span className="flex items-center gap-1"><EyeOff className="size-3.5" /> Internal only</span>
                  ) : (
                    <span className="flex items-center gap-1 text-info-ink"><Eye className="size-3.5" /> Visible to client</span>
                  )}
                </label>
              )}
            </div>
            <Button size="sm" onClick={() => post.mutate()} disabled={post.isPending || !body.trim()}>
              {post.isPending ? <Loader2 className="animate-spin" /> : <Send />}
              Post
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

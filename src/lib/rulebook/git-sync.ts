import { createHash } from "node:crypto";
import { load } from "js-yaml";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { openSealed, sealFor } from "@/lib/keys";
import { publicFetch } from "@/lib/net/public-fetch";
import { rulebookSchema } from "@/lib/rulebook/schema";
import { activeRulebook, hashRulebook, saveDraft } from "@/lib/rulebook/service";

// Policy as code: a client keeps its rulebook as YAML in its own Git
// repository, and HELIOS pulls it. A change becomes a draft that names
// where it came from; it applies only once someone signs it in HELIOS, as
// any draft does, so a commit can never change what HELIOS may do on its
// own. GitHub (contents API), GitLab (repository files API, gitlab.com or
// self-managed) or any https URL that returns the raw file. A token is
// optional (public repositories) and sealed with the client's key.

const MAX_BYTES = 200_000;

export const gitSyncSchema = z
  .object({
    provider: z.enum(["github", "gitlab", "url"]),
    repo: z.string().trim().min(3).max(300),
    host: z.string().trim().toLowerCase().max(200).default(""),
    branch: z.string().trim().min(1).max(200).default("main"),
    path: z.string().trim().transform((p) => p.replace(/^\/+/, "")).pipe(z.string().min(1).max(400)).default("helios/rulebook.yaml"),
    // Blank keeps the stored token; "-" removes it.
    token: z.string().trim().max(500).default(""),
    enabled: z.boolean().default(true),
  })
  .superRefine((c, ctx) => {
    if (c.provider === "github" && !/^[\w.-]+\/[\w.-]+$/.test(c.repo)) ctx.addIssue({ code: "custom", path: ["repo"], message: "A GitHub repository is owner/name" });
    if (c.provider === "gitlab" && !/^[\w.-]+(\/[\w.-]+)+$/.test(c.repo)) ctx.addIssue({ code: "custom", path: ["repo"], message: "A GitLab project is group/project" });
    if (c.provider === "gitlab" && c.host && !/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/.test(c.host)) ctx.addIssue({ code: "custom", path: ["host"], message: "A GitLab host is a name like gitlab.example.com" });
    if (c.provider === "url" && !/^https:\/\/\S+$/.test(c.repo)) ctx.addIssue({ code: "custom", path: ["repo"], message: "The file's address starts with https://" });
  });
export type GitSyncInput = z.input<typeof gitSyncSchema>;

type Source = { provider: string; repo: string; host: string | null; branch: string; path: string };

// Where the file is read from, and the headers that go with the token.
export function sourceRequest(s: Source, token: string | null): { url: string; headers: Record<string, string> } {
  const segments = (p: string) => p.split("/").map(encodeURIComponent).join("/");
  if (s.provider === "github") {
    return {
      url: `https://api.github.com/repos/${s.repo}/contents/${segments(s.path)}?ref=${encodeURIComponent(s.branch)}`,
      headers: { accept: "application/vnd.github.raw+json", "x-github-api-version": "2022-11-28", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    };
  }
  if (s.provider === "gitlab") {
    return {
      url: `https://${s.host || "gitlab.com"}/api/v4/projects/${encodeURIComponent(s.repo)}/repository/files/${encodeURIComponent(s.path)}/raw?ref=${encodeURIComponent(s.branch)}`,
      headers: token ? { "private-token": token } : {},
    };
  }
  return { url: s.repo, headers: token ? { authorization: `Bearer ${token}` } : {} };
}

export const describeSource = (s: Source) => (s.provider === "url" ? s.repo : `${s.provider === "github" ? "GitHub" : `GitLab${s.host ? ` (${s.host})` : ""}`} ${s.repo}@${s.branch}:${s.path}`);

export async function saveGitSync(tenantId: string, input: GitSyncInput, actorId: string) {
  const c = gitSyncSchema.parse(input);
  const before = await db.rulebookGitSync.findUnique({ where: { tenantId } });
  const tokenSealed = c.token === "-" ? null : c.token ? await sealFor(tenantId, c.token) : (before?.tokenSealed ?? null);
  const data = { provider: c.provider, repo: c.repo, host: c.provider === "gitlab" ? c.host || null : null, branch: c.branch, path: c.path, tokenSealed, enabled: c.enabled };
  // A different source starts afresh.
  const moved = !before || before.provider !== c.provider || before.repo !== c.repo || before.branch !== c.branch || before.path !== c.path || before.host !== data.host;
  const saved = await db.rulebookGitSync.upsert({
    where: { tenantId },
    create: { tenantId, ...data, createdById: actorId },
    update: { ...data, ...(moved ? { lastHash: null, lastVersion: null, lastError: null } : {}) },
  });
  await logAction({ actorId, action: "rulebook.git_sync_saved", detail: { tenantId, source: describeSource(saved), enabled: saved.enabled, token: tokenSealed ? "set" : "none" } });
  return saved;
}

export async function removeGitSync(tenantId: string, actorId: string) {
  await db.rulebookGitSync.delete({ where: { tenantId } });
  await logAction({ actorId, action: "rulebook.git_sync_removed", detail: { tenantId } });
}

async function audience(tenantId: string) {
  const admins = await db.user.findMany({ where: { tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
  return [...admins.map((a) => a.id), ...(await staffFor(["SOC_MANAGER"], null))];
}

export type SyncOutcome = { status: "imported" | "unchanged" | "in_force" | "error"; message: string; version?: number };

export async function syncRulebook(tenantId: string, opts: { fetchImpl?: typeof fetch; actor?: { id: string; name: string } } = {}): Promise<SyncOutcome> {
  const cfg = await db.rulebookGitSync.findUniqueOrThrow({ where: { tenantId } });
  const label = describeSource(cfg);
  const now = new Date();
  const fail = async (message: string): Promise<SyncOutcome> => {
    // Tell people once per distinct problem, not every hour.
    if (cfg.lastError !== message) {
      await notify(await audience(tenantId), { kind: "rulebook", title: "Rulebook sync from Git failed", body: `${label}: ${message}`, href: `/rulebook?tenant=${tenantId}` });
    }
    await db.rulebookGitSync.update({ where: { tenantId }, data: { lastCheckedAt: now, lastError: message.slice(0, 500) } });
    return { status: "error", message };
  };
  let text: string;
  try {
    const { url, headers } = sourceRequest(cfg, cfg.tokenSealed ? await openSealed(cfg.tokenSealed) : null);
    const res = await publicFetch(url, { headers }, opts.fetchImpl);
    if (!res.ok) return fail(res.status === 404 ? "the file isn't there (check the repository, branch and path, and that the token can read it)" : res.status === 401 || res.status === 403 ? `access refused (HTTP ${res.status}): check the token` : `HTTP ${res.status}`);
    text = await res.text();
  } catch (e) {
    return fail(e instanceof Error ? e.message : String(e));
  }
  if (text.length > MAX_BYTES) return fail("the file is too large for a rulebook");
  const hash = createHash("sha256").update(text).digest("hex");
  if (hash === cfg.lastHash && !cfg.lastError) {
    await db.rulebookGitSync.update({ where: { tenantId }, data: { lastCheckedAt: now } });
    return { status: "unchanged", message: "No change since the last read" };
  }
  let parsed: unknown;
  try {
    // js-yaml 4's load is safe: plain data only, no custom types.
    parsed = load(text);
  } catch (e) {
    return fail(`not valid YAML: ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`);
  }
  const body = rulebookSchema.safeParse(parsed);
  if (!body.success) {
    const issue = body.error.issues[0];
    return fail(`not a valid rulebook: ${issue.path.join(".") || "(top)"}: ${issue.message}`);
  }
  const contentHash = hashRulebook(body.data);
  const [active, open] = await Promise.all([activeRulebook(tenantId, true), db.orgPolicy.findFirst({ where: { tenantId, status: { in: ["DRAFT", "AWAITING_SIGNATURE"] } } })]);
  if (active?.hash === contentHash || open?.contentHash === contentHash) {
    await db.rulebookGitSync.update({ where: { tenantId }, data: { lastHash: hash, lastCheckedAt: now, lastError: null } });
    return active?.hash === contentHash ? { status: "in_force", message: `The rules in Git are already in force (v${active.version})` } : { status: "unchanged", message: `The open draft v${open!.version} already has these rules` };
  }
  const author = opts.actor ?? { id: cfg.createdById ?? "", name: "Git sync" };
  const draft = await saveDraft(tenantId, { body: body.data, reason: `From Git: ${label} (${hash.slice(0, 12)})`, template: "git" }, author);
  await db.rulebookGitSync.update({ where: { tenantId }, data: { lastHash: hash, lastVersion: draft.version, lastCheckedAt: now, lastError: null } });
  await notify(await audience(tenantId), {
    kind: "rulebook",
    title: `Rulebook draft v${draft.version} came from Git`,
    body: `${label}. Nothing changes until it's reviewed and signed on the rulebook page.${open ? ` It replaced the open draft v${open.version}.` : ""}`,
    href: `/rulebook?tenant=${tenantId}`,
  });
  return { status: "imported", message: `Imported as draft v${draft.version}`, version: draft.version };
}

// The job: every enabled source, each on its own.
export async function syncAllRulebooks() {
  const sources = await db.rulebookGitSync.findMany({ where: { enabled: true }, select: { tenantId: true } });
  let imported = 0;
  for (const s of sources) {
    const r = await syncRulebook(s.tenantId).catch((e) => ({ status: "error", message: String(e) }) as SyncOutcome);
    if (r.status === "imported") imported++;
  }
  return { sources: sources.length, imported };
}

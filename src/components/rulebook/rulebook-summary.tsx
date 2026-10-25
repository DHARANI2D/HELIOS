import { ACTION_MODES, AI_RESIDENCY, APPROVER_CHANNELS, MATCHER_KINDS, ON_TIMEOUT, OUT_OF_HOURS, RULED_ACTIONS, RULED_ACTION_LABEL, type Matcher, type Rulebook } from "@/lib/rulebook/schema";
import { Badge } from "@/components/ui/badge";

// A rulebook as the client reads it: plain sentences per block.

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const matcher = (m: Matcher) => `${MATCHER_KINDS[m.kind].toLowerCase()} ${m.value}${m.note ? ` — ${m.note}` : ""}`;

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border p-3">
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h4>
      <div className="flex flex-col gap-1 text-sm">{children}</div>
    </div>
  );
}

function List({ items, empty }: { items: string[]; empty: string }) {
  if (!items.length) return <p className="text-xs text-muted-foreground">{empty}</p>;
  return (
    <ul className="list-disc pl-4 text-xs">
      {items.map((i, n) => <li key={n}>{i}</li>)}
    </ul>
  );
}

export function RulebookSummary({ book }: { book: Rulebook }) {
  const fmt = (iso: string) => new Date(iso).toLocaleString("en-GB", { timeZone: book.schedule.timeZone, dateStyle: "medium", timeStyle: "short" });
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Block title="Assets">
        <p className="text-xs font-medium">Never isolated</p>
        <List items={book.assets.neverIsolate.map(matcher)} empty="No never-isolate rules." />
        <p className="mt-1 text-xs font-medium">Crown jewels (a human decides)</p>
        <List items={book.assets.crownJewels.map(matcher)} empty="No tier-1 assets." />
      </Block>
      <Block title="People">
        <p className="text-xs"><span className="font-medium">Never disabled:</span> {[...book.identities.breakGlass, ...book.identities.service].join(", ") || "none listed"}</p>
        <p className="text-xs"><span className="font-medium">VIP (approval only):</span> {book.identities.vip.join(", ") || "none listed"}</p>
      </Block>
      <Block title="Actions">
        <table className="w-full text-xs">
          <tbody>
            {RULED_ACTIONS.map((a) => {
              const r = book.actions[a];
              return (
                <tr key={a} className="border-t first:border-t-0">
                  <td className="py-1">{RULED_ACTION_LABEL[a]}</td>
                  <td className="py-1 text-right">
                    <Badge variant={r.mode === "never" ? "destructive" : r.mode === "auto" ? "success" : r.mode === "approve" ? "warning" : "outline"}>
                      {r.mode === "auto" ? `Automatic from ${r.autoFrom.toLowerCase()}` : ACTION_MODES[r.mode]}
                    </Badge>
                    {book.blastRadius.twoPerson.includes(a) && <Badge variant="outline" className="ml-1">two people</Badge>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="text-xs text-muted-foreground">
          At most {book.blastRadius.maxActionsPerHour} automatic actions an hour and {book.blastRadius.maxHostsIsolated} hosts isolated at once without a human.
        </p>
        <p className="text-xs text-muted-foreground">
          IP blocks {book.timeBoxes.blockIpHours ? `lift after ${book.timeBoxes.blockIpHours} h` : "stay until lifted"}; disabled accounts {book.timeBoxes.disableUserHours ? `re-enable after ${book.timeBoxes.disableUserHours} h` : "stay disabled until re-enabled"}, unless someone keeps them.
        </p>
      </Block>
      <Block title="Schedule">
        <p className="text-xs">
          {book.schedule.businessDays.map((d) => DAYS[d]).join(", ") || "No business days"} · {book.schedule.businessStart}–{book.schedule.businessEnd} ({book.schedule.timeZone})
        </p>
        <p className="text-xs">Outside those hours: {OUT_OF_HOURS[book.schedule.outOfHours].toLowerCase()}.</p>
        <List items={book.schedule.maintenance.map((w) => `Maintenance: ${w.label}, ${fmt(w.start)} → ${fmt(w.end)}`)} empty="No maintenance windows." />
        <List items={book.schedule.freezes.map((w) => `Change freeze: ${w.label}, ${fmt(w.start)} → ${fmt(w.end)}`)} empty="No change freezes." />
      </Block>
      <Block title="Approvers">
        <List items={book.approvers.chain.map((a, i) => `${i + 1}. ${a.name} — ${APPROVER_CHANNELS[a.channel]} (${a.contact}), ${a.timeoutMinutes} min`)} empty="No approver chain: the SOC's approvers and the client's admins are asked." />
        <p className="text-xs text-muted-foreground">If nobody answers: {ON_TIMEOUT[book.approvers.onTimeout].toLowerCase()}.</p>
      </Block>
      <Block title="Data handling and obligations">
        <p className="text-xs">AI: {AI_RESIDENCY[book.dataHandling.residency]}{book.dataHandling.residency === "region" ? ` (${book.dataHandling.regions.join(", ") || "no region set"})` : ""}; personal data {book.dataHandling.redactPii ? "masked for cloud models" : "sent as is"}; users {book.dataHandling.allowUserChoice ? "may" : "may not"} pick their own model.</p>
        <p className="text-xs">{book.obligations.regulatedEntity ? `Regulated entity · CERT-In contact: ${book.obligations.certInContact.name || "not named"}${book.obligations.certInContact.email ? ` (${book.obligations.certInContact.email})` : ""}` : "Not flagged as a regulated entity."}</p>
        <p className="text-xs text-muted-foreground">Reviewed every {book.reviewEveryDays} days.</p>
      </Block>
    </div>
  );
}

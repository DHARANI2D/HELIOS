import type { DetonationResult } from "@/lib/forensics/sandbox";
import { Badge } from "@/components/ui/badge";

export function DetonationView({ result }: { result: DetonationResult }) {
  const pillars = [
    ["Sensitive data capture", result.pillars.sensitiveDataCapture],
    ["Unauthorized target", result.pillars.unauthorizedTarget],
    ["Stealthy behaviour", result.pillars.stealthyBehavior],
  ] as const;
  return (
    <div className="rounded-md border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs break-all">{result.url}</span>
        <Badge variant={result.score >= 40 ? "destructive" : result.score > 0 ? "warning" : "secondary"}>score {result.score}</Badge>
        {result.status && <Badge variant="outline">HTTP {result.status}</Badge>}
      </div>
      {result.error ? (
        <p className="mt-2 text-xs text-muted-foreground">Not reachable: {result.error}</p>
      ) : (
        <>
          {result.title && <p className="mt-2 text-xs">Page title: <span className="font-medium">{result.title}</span></p>}
          {result.redirectChain.length > 1 && (
            <ol className="mt-2 space-y-0.5 text-xs">
              {result.redirectChain.map((h, i) => (
                <li key={i} className="font-mono break-all"><span className="text-muted-foreground">{h.status}</span> {h.url}</li>
              ))}
            </ol>
          )}
          <div className="mt-2 flex flex-wrap gap-1.5">
            {pillars.map(([label, on]) => (
              <Badge key={label} variant={on ? "destructive" : "outline"}>{label}: {on ? "yes" : "no"}</Badge>
            ))}
          </div>
          {result.html && result.html.forms.length > 0 && (
            <ul className="mt-2 space-y-1 text-xs">
              {result.html.forms.map((f, i) => (
                <li key={i}>
                  {f.method} form → <span className="font-mono break-all">{f.action || "(same page)"}</span> ({f.targetType}
                  {f.hidden ? ", hidden" : ""}) fields: {f.fields.map((x) => x.name || x.type).join(", ") || "none"}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {result.reasons.length > 0 && (
        <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs">
          {result.reasons.map((r, i) => <li key={i}>{r}</li>)}
        </ul>
      )}
      <p className="mt-2 text-[11px] text-muted-foreground">
        HTTP-level detonation — page HTML inspected, JavaScript not executed.
        {result.egress === "proxy" && " Fetched through the egress proxy."}
        {result.proxyResolved?.length ? ` ${result.proxyResolved.join(", ")} resolved by the proxy, not checked against internal ranges here.` : ""}
      </p>
    </div>
  );
}

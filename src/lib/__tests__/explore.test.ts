import { describe, expect, it } from "vitest";
import { Prisma } from "@prisma/client";

import { QueryError, bucketSeconds, filterFor, parseQuery } from "@/lib/explore/query";
import { likePattern, whereSql } from "@/lib/explore/search";
import { exploreParams, parseCursor } from "@/lib/explore/request";
import { csvCell, toCsv } from "@/lib/explore/csv";
import { builtinSuggestion } from "@/lib/explore/assistant";

describe("Explore query language", () => {
  it("parses fields, OR groups, negation, wildcards, lists, comparisons and free text", () => {
    const q = parseQuery('host:FIN-WS-04 type:LOGIN_FAIL OR type:LOGIN_SUCCESS -user:svc_* NOT src:10.* port:>1024 ip:1.2.3.4,5.6.7.8 hash:* mimikatz "lsass dump" cmd:"net user"');
    expect(q).toHaveLength(10);
    expect(q[0]).toEqual([expect.objectContaining({ kind: "field", op: "eq", values: ["FIN-WS-04"], negate: false })]);
    expect(q[1].map((t) => t.kind === "field" && t.values[0])).toEqual(["LOGIN_FAIL", "LOGIN_SUCCESS"]);
    expect(q[2][0]).toMatchObject({ negate: true, values: ["svc_*"] });
    expect(q[3][0]).toMatchObject({ negate: true, values: ["10.*"] });
    expect(q[4][0]).toMatchObject({ op: "gt", values: ["1024"] });
    expect(q[5][0]).toMatchObject({ values: ["1.2.3.4", "5.6.7.8"] });
    expect(q[6][0]).toMatchObject({ op: "exists" });
    expect(q[7][0]).toEqual({ kind: "text", value: "mimikatz", negate: false });
    expect(q[8][0]).toEqual({ kind: "text", value: "lsass dump", negate: false });
    expect(q[9][0]).toMatchObject({ values: ["net user"] });
    expect(parseQuery('cmd:"net user"')[0][0]).toMatchObject({ values: ["net user"] });
  });

  it("accepts the field names analysts bring from other tools", () => {
    expect(parseQuery("src_ip:1.2.3.4 dest_port:443 Image:*cmd.exe CommandLine:*whoami* sha256:abc")).toHaveLength(5);
    expect(parseQuery("")).toEqual([]);
    expect(parseQuery("*")).toEqual([]);
  });

  it("refuses what it can't read, in words people understand", () => {
    expect(() => parseQuery("colour:red")).toThrow(/Unknown field "colour"/);
    expect(() => parseQuery("host:>5")).toThrow(/isn't a number/);
    expect(() => parseQuery("port:abc")).toThrow(/whole numbers/);
    expect(() => parseQuery('cmd:"open')).toThrow(/quote/);
    expect(() => parseQuery("OR host:a")).toThrow(/OR needs/);
    expect(() => parseQuery("host:a OR")).toThrow(/OR needs/);
    expect(() => parseQuery("host:")).toThrow(/needs a value/);
    expect(() => parseQuery("x".repeat(2001))).toThrow(QueryError);
    expect(() => parseQuery(Array.from({ length: 41 }, (_, i) => `w${i}`).join(" "))).toThrow(/At most 40/);
  });

  it("compiles to parameters, never to SQL text from the search", () => {
    const evil = `'; DROP TABLE security_events; --`;
    const sql = whereSql(parseQuery(`host:"${evil}" ${'"x\' OR 1=1 --"'} port:<=80`), { tenantId: "t1" }, new Date("2026-11-01T00:00:00Z"), new Date("2026-11-02T00:00:00Z"));
    expect(sql.sql).not.toContain("DROP");
    expect(sql.sql).not.toContain("1=1");
    // The value travels as a bound parameter (a LIKE pattern: _ escaped).
    expect(sql.values).toContain(evil.replace("_", "\\_"));
    expect(sql.values).toContain("t1");
    expect(sql.text).toContain('"tenantId" = $');
    expect(sql.text).toMatch(/"destPort" <= \$\d+/);
    // Excluding a value keeps events with no value.
    expect(whereSql(parseQuery("-user:bob"), { tenantId: null }, new Date(0), new Date(1)).sql).toContain("NOT COALESCE(");
    expect(Prisma.sql`x`.sql).toBe("x");
  });

  it("treats % and _ as literal and * as the wildcard", () => {
    expect(likePattern("50%_off*")).toBe("50\\%\\_off%");
    expect(likePattern("lsass", true)).toBe("%lsass%");
    expect(likePattern("*lsass*", true)).toBe("%lsass%");
  });

  it("builds a filter from a clicked value, quoting when needed", () => {
    expect(filterFor("host", "FIN-WS-04")).toBe("host:FIN-WS-04");
    expect(filterFor("cmd", 'net user "x"', true)).toBe('-cmd:"net user \\"x\\""');
    expect(parseQuery(filterFor("cmd", 'net user "x"'))[0][0]).toMatchObject({ values: ['net user "x"'] });
  });

  it("picks about sixty round histogram bars", () => {
    expect(bucketSeconds(0, 3_600_000)).toBe(60);
    expect(bucketSeconds(0, 86_400_000)).toBe(1800);
    expect(bucketSeconds(0, 30 * 86_400_000)).toBe(43_200);
  });
});

describe("Explore requests", () => {
  const staff = { isClient: false, tenantId: null };
  const client = { isClient: true, tenantId: "client-a" };
  const now = new Date("2026-11-01T12:00:00Z");

  it("pins a client user to their own client whatever they ask for", () => {
    expect(exploreParams({ tenant: "client-b" }, client, null, now).tenant).toBe("client-a");
    expect(exploreParams({ tenant: "all" }, client, null, now).tenant).toBe("client-a");
    expect(exploreParams({}, { isClient: true, tenantId: null }, null, now).tenant).toBe("__none__");
  });

  it("lets staff pick a client or all, defaulting to the one selected in the header", () => {
    expect(exploreParams({ tenant: "client-b" }, staff, "client-a", now).tenant).toBe("client-b");
    expect(exploreParams({ tenant: "all" }, staff, "client-a", now).tenant).toBeNull();
    expect(exploreParams({}, staff, "client-a", now).tenant).toBe("client-a");
  });

  it("reads ranges and custom windows", () => {
    const p = exploreParams({ range: "1h" }, staff, null, now);
    expect(now.getTime() - p.from.getTime()).toBe(3_600_000);
    expect(exploreParams({ range: "bogus" }, staff, null, now).range).toBe("24h");
    const c = exploreParams({ from: "2026-10-01T00:00:00Z", to: "2026-10-02T00:00:00Z" }, staff, null, now);
    expect(c.range).toBe("custom");
    expect(() => exploreParams({ from: "yesterday" }, staff, null, now)).toThrow(QueryError);
    expect(parseCursor("2026-11-01T00:00:00.000Z|abc123")).toEqual({ t: "2026-11-01T00:00:00.000Z", id: "abc123" });
    expect(() => parseCursor("x|y")).toThrow(QueryError);
    expect(() => parseCursor("2026-11-01T00:00:00Z|a b")).toThrow(QueryError);
  });
});

describe("CSV export", () => {
  it("escapes quotes and line breaks, and defuses formulas", () => {
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell("=HYPERLINK(\"http://x\")")).toBe("\"'=HYPERLINK(\"\"http://x\"\")\"");
    expect(csvCell("-enc AAA")).toBe("'-enc AAA");
    expect(csvCell("@SUM(1)")).toBe("'@SUM(1)");
    expect(csvCell(null)).toBe("");
    expect(toCsv(["a", "b"], [[1, "x\ny"]])).toBe('a,b\r\n1,"x\ny"\r\n');
  });
});

describe("Search assistant (built-in)", () => {
  it("turns common questions into searches HELIOS can run", () => {
    const a = builtinSuggestion("Failed sign-ins for user alice in the last 24 hours");
    expect(a.query).toContain("type:LOGIN_FAIL");
    expect(a.query).toContain("user:alice");
    expect(a.range).toBe("24h");
    const b = builtinSuggestion("powershell with encoded commands on host FIN-WS-04 this week");
    expect(b.query).toContain("process:*powershell*");
    expect(b.query).toContain('cmd:"*-enc*"');
    expect(b.query).toContain("host:FIN-WS-04*");
    expect(b.range).toBe("7d");
    expect(builtinSuggestion("connections to 203.0.113.7 on port 4444").query).toBe("ip:203.0.113.7 port:4444");
    for (const s of [a, b, builtinSuggestion("anything about rclone exfiltration")]) expect(() => parseQuery(s.query)).not.toThrow();
  });
});

import { createHash } from "node:crypto";
import { z } from "zod";

// The HELIOS forwarder is a stock Fluent Bit (3.x or later) running a
// configuration HELIOS generates from the onboarding answers: syslog from
// firewalls and network gear, Windows event logs, and log files, buffered
// to disk, compressed, and sent over HTTPS to the client's ingest URL with
// its token. The token stays out of the file (an environment variable).
// The configuration is hashed and signed: the forwarder sends the hash with
// every request (X-Helios-Config), so HELIOS can tell which issued
// configuration each forwarder runs, and anyone can check a configuration
// file against the signature HELIOS issued it with (verifyConfig). Neither
// stops an administrator of the box from editing it; source health
// (lib/ingest/health) catches a forwarder that goes quiet.
// Pure.

export const WINDOWS_CHANNELS = {
  security: {
    label: "Security",
    channel: "Security",
    // Logons, process creation, account and group changes, scheduled tasks, log cleared.
    query: "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4647 or EventID=4648 or EventID=4688 or EventID=4698 or EventID=1102 or (EventID>=4720 and EventID<=4767))]]",
  },
  system: { label: "System", channel: "System", query: "*[System[(EventID=7045 or EventID=104)]]" },
  sysmon: { label: "Sysmon", channel: "Microsoft-Windows-Sysmon/Operational", query: "*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=22)]]" },
  powershell: { label: "PowerShell script blocks", channel: "Microsoft-Windows-PowerShell/Operational", query: "*[System[(EventID=4104)]]" },
} as const;

export type WindowsChannel = keyof typeof WINDOWS_CHANNELS;

export const ForwarderOptionsSchema = z.object({
  os: z.enum(["linux", "windows"]),
  syslog: z
    .object({
      udpPort: z.number().int().min(1).max(65535).nullable(),
      tcpPort: z.number().int().min(1).max(65535).nullable(),
      format: z.enum(["rfc3164", "rfc5424"]),
    })
    .nullable(),
  windowsChannels: z.array(z.enum(Object.keys(WINDOWS_CHANNELS) as [WindowsChannel, ...WindowsChannel[]])),
  files: z.array(z.string().trim().min(1).max(300).regex(/^[^\n\r[\]]+$/, "One path per line, no brackets")).max(20),
  bufferLimitMb: z.number().int().min(64).max(100_000),
});

export type ForwarderOptions = z.infer<typeof ForwarderOptionsSchema>;

export const DEFAULT_OPTIONS: ForwarderOptions = {
  os: "linux",
  syslog: { udpPort: 514, tcpPort: null, format: "rfc3164" },
  windowsChannels: [],
  files: [],
  bufferLimitMb: 2048,
};

export interface IssuedConfig {
  text: string;
  hash: string;
  signature: string;
}

function section(name: string, entries: Array<[string, string | number] | null>) {
  const rows = entries.filter((e): e is [string, string | number] => !!e);
  const width = Math.max(...rows.map(([k]) => k.length));
  return [`[${name}]`, ...rows.map(([k, v]) => `    ${k.padEnd(width)} ${v}`)].join("\n");
}

// Everything but the signature lines, which can't sign themselves.
export function configBody(text: string) {
  return text
    .split("\n")
    .filter((l) => !l.startsWith("# helios-config-hash:") && !l.startsWith("# helios-signature:"))
    .join("\n")
    .trim();
}

export function renderConfig(o: ForwarderOptions, target: { ingestUrl: string; label: string; issuedAt: Date }, sign: (hash: string) => string): IssuedConfig {
  const url = new URL(target.ingestUrl);
  const windows = o.os === "windows";
  const state = windows ? "C:\\ProgramData\\helios-forwarder" : "/var/lib/helios-forwarder";
  const sep = windows ? "\\" : "/";
  const sections: string[] = [];

  sections.push(
    section("SERVICE", [
      ["flush", 5],
      ["log_level", "info"],
      ["parsers_file", "parsers.conf"],
      // Survives restarts and outages: chunks wait on disk until HELIOS accepts them.
      ["storage.path", `${state}${sep}buffer`],
      ["storage.sync", "normal"],
      ["storage.backlog.mem_limit", "50M"],
    ]),
  );
  if (o.syslog) {
    for (const [mode, port] of [["udp", o.syslog.udpPort], ["tcp", o.syslog.tcpPort]] as const) {
      if (!port) continue;
      sections.push(
        section("INPUT", [
          ["name", "syslog"],
          ["tag", `syslog.${mode}`],
          ["mode", mode],
          ["listen", "0.0.0.0"],
          ["port", port],
          ["parser", `syslog-${o.syslog.format}`],
          ["storage.type", "filesystem"],
        ]),
      );
    }
  }
  if (windows) {
    for (const key of o.windowsChannels) {
      const c = WINDOWS_CHANNELS[key];
      sections.push(
        section("INPUT", [
          ["name", "winevtlog"],
          ["tag", `win.${key}`],
          ["channels", c.channel],
          ["event_query", c.query],
          ["string_inserts", "on"],
          ["interval_sec", 1],
          ["db", `${state}${sep}winevtlog-${key}.sqlite`],
          ["storage.type", "filesystem"],
        ]),
      );
    }
  }
  o.files.forEach((path, i) => {
    sections.push(
      section("INPUT", [
        ["name", "tail"],
        ["tag", `file.${i}`],
        ["path", path],
        ["path_key", "helios_file"],
        ["db", `${state}${sep}tail.sqlite`],
        ["skip_long_lines", "on"],
        ["storage.type", "filesystem"],
      ]),
    );
  });
  // Each record says which input it came from, so the ingest mappers needn't guess.
  for (const [match, input] of [["syslog.*", "syslog"], ["win.*", "windows"], ["file.*", "file"]] as const) {
    if (match === "win.*" && !(windows && o.windowsChannels.length)) continue;
    if (match === "syslog.*" && !o.syslog) continue;
    if (match === "file.*" && !o.files.length) continue;
    sections.push(section("FILTER", [["name", "modify"], ["match", match], ["add", `helios_input ${input}`]]));
  }

  const body = (hash: string) =>
    section("OUTPUT", [
      ["name", "http"],
      ["match", "*"],
      ["host", url.hostname],
      ["port", url.port || (url.protocol === "http:" ? 80 : 443)],
      ["uri", url.pathname],
      ["format", "json_lines"],
      ["json_date_key", "timestamp"],
      ["json_date_format", "iso8601"],
      ["header", "Authorization Bearer ${HELIOS_INGEST_TOKEN}"],
      ["header", `X-Helios-Config ${hash}`],
      ["compress", "gzip"],
      ["tls", url.protocol === "https:" ? "on" : "off"],
      ["tls.verify", url.protocol === "https:" ? "on" : "off"],
      ["retry_limit", "no_limits"],
      ["storage.total_limit_size", `${o.bufferLimitMb}M`],
    ]);

  const header = [
    `# HELIOS log forwarder for ${target.label.replace(/[\r\n]/g, " ")}`,
    `# Issued ${target.issuedAt.toISOString()} for Fluent Bit 3.x or later (${windows ? "Windows" : "Linux"}).`,
    "# Set HELIOS_INGEST_TOKEN in the service's environment to the ingest token shown at onboarding.",
    "# Editing this file changes its hash: HELIOS then shows the forwarder as running a configuration it didn't issue.",
  ].join("\n");
  const draft = (hash: string) => `${header}\n\n${sections.join("\n\n")}\n\n${body(hash)}\n`;
  // The file names its own hash (in the output's header), so the hash is
  // taken over the file with a placeholder there; configHashOf does the same.
  const placeholder = "0".repeat(64);
  const hash = createHash("sha256").update(configBody(draft(placeholder))).digest("hex");
  const text = draft(hash);
  const signature = sign(hash);
  return { text: `${text}# helios-config-hash: ${hash}\n# helios-signature: ${signature}\n`, hash, signature };
}

// A file's hash, recomputed with the placeholder in place of the hash it names.
export function configHashOf(text: string) {
  const hash = text.match(/^# helios-config-hash: ([a-f0-9]{64})$/m)?.[1];
  const withPlaceholder = configBody(text).replace(/X-Helios-Config [a-f0-9]{64}/, `X-Helios-Config ${"0".repeat(64)}`);
  return { claimed: hash ?? null, actual: createHash("sha256").update(withPlaceholder).digest("hex") };
}

export function verifyConfig(text: string, sign: (hash: string) => string): { ok: boolean; hash: string; reason: string } {
  const { claimed, actual } = configHashOf(text);
  const signature = text.match(/^# helios-signature: ([a-f0-9]{64})$/m)?.[1];
  const header = text.match(/X-Helios-Config ([a-f0-9]{64})/)?.[1];
  if (!claimed || !signature) return { ok: false, hash: actual, reason: "The file has no HELIOS hash and signature lines" };
  if (claimed !== actual || header !== actual) return { ok: false, hash: actual, reason: "The file was changed after HELIOS issued it" };
  if (sign(actual) !== signature) return { ok: false, hash: actual, reason: "The signature doesn't match: this HELIOS didn't issue it" };
  return { ok: true, hash: actual, reason: "Issued by HELIOS and unchanged" };
}

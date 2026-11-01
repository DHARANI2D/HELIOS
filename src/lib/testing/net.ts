import { promises as dns } from "node:dns";
import { createConnection, isIP } from "node:net";
import { connect as tlsConnect, type PeerCertificate } from "node:tls";

import { isPrivateAddress } from "@/lib/net/public-fetch";
import type { CertInfo, Net } from "@/lib/testing/exposure";

// The network side of the exposure check, for real. Every probe refuses a
// private or internal address, whatever the caller passed: HELIOS never
// scans inside anyone's network from here.

function assertPublic(ip: string) {
  if (!isIP(ip) || isPrivateAddress(ip)) throw new Error(`${ip} isn't a public address`);
}

export const liveNet: Net = {
  async addresses(name) {
    const [v4, v6] = await Promise.all([dns.resolve4(name).catch(() => [] as string[]), dns.resolve6(name).catch(() => [] as string[])]);
    return [...v4, ...v6];
  },
  txt: (name) => dns.resolveTxt(name),
  connect(ip, port, timeoutMs) {
    assertPublic(ip);
    return new Promise((resolve) => {
      let banner = "";
      let opened = false;
      const socket = createConnection({ host: ip, port, timeout: timeoutMs });
      const done = () => {
        socket.destroy();
        resolve({ open: opened, banner: banner.replace(/[^\x20-\x7e]+/g, " ").trim().slice(0, 200) || null });
      };
      socket.once("connect", () => {
        opened = true;
        // Only listen: a service that greets (SSH, FTP, SMTP) says who it is.
        setTimeout(done, 1200);
      });
      socket.on("data", (d) => {
        banner += d.toString("latin1");
        if (banner.length > 256) done();
      });
      socket.once("timeout", done);
      socket.once("error", done);
    });
  },
  tls(ip, port, servername, timeoutMs) {
    assertPublic(ip);
    return new Promise((resolve) => {
      const socket = tlsConnect({ host: ip, port, servername: servername ?? undefined, rejectUnauthorized: false, timeout: timeoutMs, ALPNProtocols: ["http/1.1"] });
      const finish = (v: CertInfo | null) => {
        socket.destroy();
        resolve(v);
      };
      socket.once("secureConnect", () => {
        const c = socket.getPeerCertificate() as PeerCertificate | undefined;
        if (!c || !c.valid_to) return finish(null);
        const cn = (x: unknown) => (Array.isArray(x) ? x.join(", ") : String(x ?? ""));
        const names = [...(c.subjectaltname ?? "").split(/,\s*/).filter((n) => n.startsWith("DNS:")).map((n) => n.slice(4)), cn(c.subject?.CN)].filter(Boolean);
        finish({
          subject: cn(c.subject?.CN) || cn(c.subject?.O),
          issuer: cn(c.issuer?.CN) || cn(c.issuer?.O),
          validTo: new Date(c.valid_to).toISOString(),
          names,
          selfSigned: /SELF_SIGNED/.test(String(socket.authorizationError ?? "")),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          protocol: socket.getProtocol(),
        });
      });
      socket.once("timeout", () => finish(null));
      socket.once("error", () => finish(null));
    });
  },
  async http(url, timeoutMs) {
    const u = new URL(url);
    const addrs = await this.addresses(u.hostname);
    if (!addrs.length || addrs.some(isPrivateAddress)) return null;
    const res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(timeoutMs), headers: { "user-agent": "HELIOS-exposure-check/1 (authorised security test)" } });
    await res.body?.cancel().catch(() => undefined);
    return { status: res.status, headers: Object.fromEntries([...res.headers.entries()].map(([k, v]) => [k.toLowerCase(), v])) };
  },
};

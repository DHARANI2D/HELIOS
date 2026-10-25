import { createServer, request as httpRequest, type Server } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { detonateUrl, detonationProxy } from "@/lib/forensics/sandbox";

// A phishing page on loopback, reachable only through a test proxy that
// maps the made-up host phish.example.test onto it — the way an egress
// proxy resolves names the server itself can't.
const PAGE = `<html><head><title>Sign in</title></head><body><form action="https://collect.drop-site.test/submit" method="post"><input name="email"><input type="password" name="passwd"></form></body></html>`;
let target: Server;
let proxy: Server;
const seen: string[] = [];

beforeAll(async () => {
  target = createServer((_req, res) => res.writeHead(200, { "content-type": "text/html" }).end(PAGE));
  await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
  const targetPort = (target.address() as AddressInfo).port;
  proxy = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    const upstream = httpRequest({ host: "127.0.0.1", port: targetPort, path: new URL(req.url!).pathname, method: req.method, headers: req.headers }, (up) => {
      res.writeHead(up.statusCode ?? 502, up.headers);
      up.pipe(res);
    });
    req.pipe(upstream);
  });
  proxy.on("connect", (req, socket, head) => {
    seen.push(`CONNECT ${req.url}`);
    const upstream = connect(targetPort, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
  });
  await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", r));
  process.env.DETONATION_PROXY = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
});

afterAll(() => {
  delete process.env.DETONATION_PROXY;
  target.close();
  proxy.close();
});

describe("detonation through an egress proxy", () => {
  it("picks the proxy by scheme, with DETONATION_PROXY taking precedence", () => {
    const saved = process.env.DETONATION_PROXY;
    delete process.env.DETONATION_PROXY;
    process.env.HTTPS_PROXY = "http://egress.example.test:3128";
    process.env.HTTP_PROXY = "";
    expect(detonationProxy("https://a.example/")).toBe("http://egress.example.test:3128");
    expect(detonationProxy("http://a.example/")).toBeUndefined();
    process.env.DETONATION_PROXY = "none";
    expect(detonationProxy("https://a.example/")).toBeUndefined();
    delete process.env.HTTPS_PROXY;
    delete process.env.HTTP_PROXY;
    process.env.DETONATION_PROXY = saved;
  });

  it("fetches and analyzes the page through the proxy", async () => {
    const r = await detonateUrl("http://phish.example.test/login");
    expect(r.error).toBeUndefined();
    expect(r.egress).toBe("proxy");
    expect(r.proxyResolved).toEqual(["phish.example.test"]);
    expect(r.title).toBe("Sign in");
    expect(r.pillars).toMatchObject({ sensitiveDataCapture: true, unauthorizedTarget: true });
    expect(seen.some((s) => s.includes("phish.example.test"))).toBe(true);
  });

  it.each(["http://10.0.0.5/admin", "http://127.0.0.1/", "http://intranet.local/", "http://fileserver/"])("still refuses internal targets (%s)", async (url) => {
    const before = seen.length;
    const r = await detonateUrl(url);
    expect(r.error).toMatch(/Refusing/);
    expect(seen.length).toBe(before); // never reached the proxy
  });
});

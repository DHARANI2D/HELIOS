import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

import { signAws } from "@/lib/collectors/auth";

// Where archived events live: a directory on the server, or an S3 bucket
// (or an S3-compatible store) in a region the operator chooses. For
// CERT-In's "within Indian jurisdiction", that's an Indian region such as
// AWS ap-south-1 (Mumbai) or ap-south-2 (Hyderabad). Objects are already
// encrypted before they get here (lib/retention/archive.ts).
//
//   HELIOS_ARCHIVE_S3_BUCKET, HELIOS_ARCHIVE_S3_REGION, AWS_ACCESS_KEY_ID,
//   AWS_SECRET_ACCESS_KEY (AWS_SESSION_TOKEN), HELIOS_ARCHIVE_S3_ENDPOINT for
//   an S3-compatible store; or HELIOS_ARCHIVE_DIR for a directory.
//   HELIOS_DATA_REGION says where the database and a directory store are.

export interface ArchiveStore {
  kind: "local" | "s3";
  // Where the data sits, for the residency check.
  region: string | null;
  describe: string;
  put(key: string, body: Buffer): Promise<void>;
  get(key: string): Promise<Buffer>;
  remove(key: string): Promise<void>;
}

function localStore(dir: string): ArchiveStore {
  const root = path.resolve(dir);
  const full = (key: string) => {
    const p = path.resolve(root, key);
    if (!p.startsWith(`${root}${path.sep}`)) throw new Error("Archive key escapes the archive directory");
    return p;
  };
  return {
    kind: "local",
    region: process.env.HELIOS_DATA_REGION?.trim() || null,
    describe: `directory ${root}`,
    async put(key, body) {
      const p = full(key);
      await mkdir(path.dirname(p), { recursive: true });
      // Written whole, then moved into place: a crash never leaves half a file.
      await writeFile(`${p}.partial`, body);
      await rename(`${p}.partial`, p);
    },
    get: (key) => readFile(full(key)),
    async remove(key) {
      await unlink(full(key)).catch((err: NodeJS.ErrnoException) => {
        if (err.code !== "ENOENT") throw err;
      });
    },
  };
}

function s3Store(bucket: string, region: string): ArchiveStore {
  const endpoint = process.env.HELIOS_ARCHIVE_S3_ENDPOINT?.replace(/\/+$/, "");
  const creds = { accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? "", secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? "", sessionToken: process.env.AWS_SESSION_TOKEN || undefined };
  const url = (key: string) => (endpoint ? `${endpoint}/${bucket}/${key}` : `https://${bucket}.s3.${region}.amazonaws.com/${key}`);
  const call = async (method: "PUT" | "GET" | "DELETE", key: string, body?: Buffer) => {
    if (!creds.accessKeyId || !creds.secretAccessKey) throw new Error("The archive bucket needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
    const target = url(key);
    const headers = signAws({ method, url: target, region, service: "s3", body: body ?? "", now: new Date(), contentSha256Header: true, headers: body ? { "content-type": "application/octet-stream" } : {} }, creds);
    const res = await fetch(target, { method, headers, body: body ? new Uint8Array(body) : undefined, signal: AbortSignal.timeout(60_000) });
    if (!res.ok && !(method === "DELETE" && res.status === 404)) throw new Error(`S3 ${method} ${key}: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
    return res;
  };
  return {
    kind: "s3",
    region,
    describe: `${endpoint ? `${endpoint}/` : "s3://"}${bucket} (${region})`,
    async put(key, body) {
      await call("PUT", key, body);
    },
    async get(key) {
      return Buffer.from(await (await call("GET", key)).arrayBuffer());
    },
    async remove(key) {
      await call("DELETE", key);
    },
  };
}

export function archiveStore(): ArchiveStore | null {
  const bucket = process.env.HELIOS_ARCHIVE_S3_BUCKET?.trim();
  if (bucket) return s3Store(bucket, process.env.HELIOS_ARCHIVE_S3_REGION?.trim() || "ap-south-1");
  const dir = process.env.HELIOS_ARCHIVE_DIR?.trim();
  return dir ? localStore(dir) : null;
}

// Indian jurisdiction, as far as the configuration says: an AWS Indian
// region, or a region the operator declares as India.
export const inIndia = (region: string | null) => !!region && /^(ap-south-[12]|in|india|in-[a-z]+)$/i.test(region.trim());

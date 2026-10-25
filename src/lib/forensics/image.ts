import sharp, { type Metadata } from "sharp";
import jsQR from "jsqr";
import { createWorker, type Worker } from "tesseract.js";

// What's inside an image attachment: QR codes (quishing — a link the mail
// gateway never sees as text) and printed text (a lure rendered as a picture
// to dodge content filters). Decoding is sharp; QR is jsQR; OCR is Tesseract
// with English data shipped in node_modules, so nothing is downloaded at run
// time and air-gapped deployments work. Desas OCR'd images the same way with
// pytesseract.

export interface ImageFindings {
  width: number;
  height: number;
  text: string; // OCR text, whitespace-collapsed
  qr: string[]; // decoded QR payloads
  error?: string;
}

const MAX_PIXELS = 40_000_000; // refuse decompression bombs
const OCR_MAX_SIDE = 2400;
const QR_MAX_SIDE = 1600;
const OCR_TIMEOUT_MS = 30_000;

export function isRasterImage(b: Uint8Array): boolean {
  if (b.length < 12) return false;
  const png = b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47;
  const jpeg = b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  const gif = b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46;
  const webp = b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50;
  const tiff = (b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2a) || (b[0] === 0x4d && b[1] === 0x4d && b[3] === 0x2a);
  return png || jpeg || gif || webp || tiff;
}

// One OCR worker per process, used for one image at a time.
let worker: Promise<Worker> | null = null;
let queue: Promise<unknown> = Promise.resolve();

async function ocrWorker(): Promise<Worker> {
  worker ??= (async () => {
    const { langPath } = (await import("@tesseract.js-data/eng")).default as { langPath: string };
    // cacheMethod "none": read the bundled data, never write a copy into cwd.
    return createWorker("eng", 1, { langPath, gzip: true, cacheMethod: "none" });
  })().catch((err) => {
    worker = null;
    throw err;
  });
  return worker;
}

async function ocr(png: Buffer): Promise<string> {
  const run = queue.then(async () => {
    const w = await ocrWorker();
    let timer: NodeJS.Timeout | undefined;
    try {
      const result = await Promise.race([
        w.recognize(png),
        new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error("OCR timed out")), OCR_TIMEOUT_MS))),
      ]);
      return result.data.text;
    } catch (err) {
      // A stuck worker is replaced rather than reused.
      worker = null;
      void w.terminate().catch(() => {});
      throw err;
    } finally {
      clearTimeout(timer);
    }
  });
  queue = run.catch(() => {});
  return run;
}

export async function inspectImage(bytes: Uint8Array, options: { ocr?: boolean } = {}): Promise<ImageFindings> {
  const input = sharp(bytes, { limitInputPixels: MAX_PIXELS, animated: false, failOn: "error" });
  let meta: Metadata;
  try {
    meta = await input.metadata();
  } catch (err) {
    return { width: 0, height: 0, text: "", qr: [], error: `Unreadable image: ${err instanceof Error ? err.message : String(err)}` };
  }
  const findings: ImageFindings = { width: meta.width ?? 0, height: meta.height ?? 0, text: "", qr: [] };

  try {
    const { data, info } = await sharp(bytes, { limitInputPixels: MAX_PIXELS, animated: false })
      .rotate()
      .resize({ width: QR_MAX_SIDE, height: QR_MAX_SIDE, fit: "inside", withoutEnlargement: true })
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    const code = jsQR(new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength), info.width, info.height, { inversionAttempts: "attemptBoth" });
    if (code?.data) findings.qr.push(code.data);
  } catch (err) {
    findings.error = `QR scan failed: ${err instanceof Error ? err.message : String(err)}`;
  }

  if (options.ocr !== false) {
    try {
      // Grayscale, upscaled small images, flattened onto white: what
      // Tesseract reads best.
      const png = await sharp(bytes, { limitInputPixels: MAX_PIXELS, animated: false })
        .rotate()
        .flatten({ background: "#ffffff" })
        .grayscale()
        .resize({ width: OCR_MAX_SIDE, height: OCR_MAX_SIDE, fit: "inside", withoutEnlargement: (meta.width ?? 0) >= 1000 })
        .png()
        .toBuffer();
      findings.text = (await ocr(png)).replace(/[ \t]+/g, " ").replace(/\n{2,}/g, "\n").trim();
    } catch (err) {
      findings.error = `OCR failed: ${err instanceof Error ? err.message : String(err)}`;
    }
  }
  return findings;
}

// For tests and graceful shutdown.
export async function stopOcr() {
  const w = worker;
  worker = null;
  if (w) await (await w).terminate();
}

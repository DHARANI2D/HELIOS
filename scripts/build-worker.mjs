// Bundles the background worker (src/worker.ts) into one file,
// dist/worker.mjs, that runs with plain `node` from the standalone server's
// directory (the container image). Packages that load files by path at run
// time stay out of the bundle and load from the standalone server's
// node_modules, as they do for the web server: Prisma (its query engine),
// Tesseract (its worker and language data) and pdfkit (its standard fonts,
// required through its package import map).
// Next.js is bundled: the worker uses only after(), which outside a request
// throws and the caller runs the job itself.
import { build } from "esbuild";

const external = ["@prisma/client", ".prisma/client", "tesseract.js", "@tesseract.js-data/eng", "pdfkit"];

const result = await build({
  entryPoints: ["src/worker.ts"],
  outfile: "dist/worker.mjs",
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  tsconfig: "tsconfig.json",
  external,
  // Bundled CommonJS packages call require() and read __dirname.
  banner: {
    js: [
      'import { createRequire as __heliosRequire } from "node:module";',
      'import { fileURLToPath as __heliosPath } from "node:url";',
      'import { dirname as __heliosDir } from "node:path";',
      "const require = __heliosRequire(import.meta.url);",
      "const __filename = __heliosPath(import.meta.url);",
      "const __dirname = __heliosDir(__filename);",
    ].join("\n"),
  },
  sourcemap: true,
  legalComments: "linked",
  metafile: true,
  logLevel: "warning",
});

const inputs = Object.keys(result.metafile.inputs).length;
const bytes = Object.values(result.metafile.outputs).reduce((n, o) => n + o.bytes, 0);
console.log(`dist/worker.mjs: ${inputs} modules, ${(bytes / 1048576).toFixed(1)} MB (external: ${external.join(", ")})`);

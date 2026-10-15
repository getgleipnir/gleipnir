#!/usr/bin/env node
/**
 * Build the browser verifier page: site/verify/index.html, one self-contained file.
 *
 * Bundles site/verify/src/app.js with @getgleipnir/verify (from source) using esbuild, and
 * inlines the result into site/verify/src/page.html. The Content-Security-Policy allows only
 * that exact script (by SHA-256) and no network connections, so the page cannot upload the
 * bundle it checks, and it works when saved and opened from disk.
 *
 * Usage (in typescript/): npm run build:site
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
const SITE = join(HERE, "../../site/verify");

/** The page's HTML, built from the sources (deterministic). */
export async function buildPage() {
  const result = await build({
    entryPoints: [join(SITE, "src/app.js")],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    minify: true,
    legalComments: "none",
    write: false,
    alias: { "@getgleipnir/verify": join(HERE, "../packages/verify/src/index.ts") },
    logLevel: "warning",
  });
  let js = result.outputFiles[0].text.trimEnd();
  js = js.replaceAll("</script", "<\\/script");
  const hash = "sha256-" + createHash("sha256").update(js, "utf8").digest("base64");
  const page = readFileSync(join(SITE, "src/page.html"), "utf8");
  if (!page.includes("__SCRIPT__") || !page.includes("__SCRIPT_HASH__")) throw new Error("page.html placeholders missing");
  return page.replace("__SCRIPT_HASH__", hash).replace("__SCRIPT__", () => js);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const out = await buildPage();
  writeFileSync(join(SITE, "index.html"), out);
  console.log(`wrote site/verify/index.html (${(out.length / 1024).toFixed(0)} KiB)`);
}

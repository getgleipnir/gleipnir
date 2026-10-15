#!/usr/bin/env node
/**
 * Build the static pages, each one self-contained file:
 *
 * - site/verify/index.html: the browser verifier;
 * - site/approve/index.html: passkey approval of one exact agent action (no backend).
 *
 * Bundles site/<page>/src/app.js with @getgleipnir/verify (from source) using esbuild, and
 * inlines the result into site/<page>/src/page.html. The Content-Security-Policy allows only
 * that exact script (by SHA-256) and no network connections, so the pages cannot upload anything,
 * and they work when saved and opened from disk (passkeys need https or localhost).
 *
 * Usage (in typescript/): npm run build:site
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
export const PAGES = ["verify", "approve"];

/** A page's HTML, built from its sources (deterministic). */
export async function buildPage(name = "verify") {
  const site = join(HERE, "../../site", name);
  const result = await build({
    entryPoints: [join(site, "src/app.js")],
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
  const page = readFileSync(join(site, "src/page.html"), "utf8");
  if (!page.includes("__SCRIPT__") || !page.includes("__SCRIPT_HASH__")) throw new Error(`${name}/src/page.html placeholders missing`);
  return page.replace("__SCRIPT_HASH__", hash).replace("__SCRIPT__", () => js);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  for (const name of PAGES) {
    const out = await buildPage(name);
    writeFileSync(join(HERE, "../../site", name, "index.html"), out);
    console.log(`wrote site/${name}/index.html (${(out.length / 1024).toFixed(0)} KiB)`);
  }
}

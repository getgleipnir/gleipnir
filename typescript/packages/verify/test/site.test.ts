/** The static browser verifier page (site/verify/index.html, built by `npm run build:site`). */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SITE = fileURLToPath(new URL("../../../../site/verify/", import.meta.url));

describe("site/verify/index.html", () => {
  const html = readFileSync(SITE + "index.html", "utf8");
  const script = /<script type="module">([\s\S]*)<\/script>/.exec(html)?.[1] ?? "";

  it("is one self-contained file: a single inline script pinned by hash, no network access", () => {
    expect(script.length).toBeGreaterThan(10000);
    const csp = /Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] ?? "";
    const hash = "sha256-" + createHash("sha256").update(script, "utf8").digest("base64");
    expect(csp).toContain(`script-src '${hash}'`);
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("default-src 'none'");
    expect(html).not.toMatch(/<script[^>]+src=|<link[^>]+href=|@import/);
    expect(script).not.toMatch(/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource/);
  });

  it("says that nothing is uploaded, and offers the checks", () => {
    expect(html).toContain("Nothing is uploaded");
    for (const id of ["expect-key", "known-head", "req-rekor", "req-rfc3161", "require-full", "max-delay", "expect-until"]) {
      expect(html).toContain(`id="${id}"`);
    }
  });

  it("is up to date with site/verify/src and the verifier source (run `npm run build:site`)", async () => {
    // @ts-expect-error: plain .mjs build script
    const { buildPage } = await import("../../../scripts/build-site.mjs");
    expect((await buildPage()) === html, "site/verify/index.html is stale: run `npm run build:site`").toBe(true);
  });
});

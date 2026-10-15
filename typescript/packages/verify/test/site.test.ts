/** The static pages (site/verify/index.html, site/approve/index.html, built by `npm run build:site`). */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SITE = fileURLToPath(new URL("../../../../site/", import.meta.url));

for (const name of ["verify", "approve"]) {
  describe(`site/${name}/index.html`, () => {
    const html = readFileSync(SITE + name + "/index.html", "utf8");
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

    it(`is up to date with site/${name}/src and the verifier source (run \`npm run build:site\`)`, async () => {
      // @ts-expect-error: plain .mjs build script
      const { buildPage } = await import("../../../scripts/build-site.mjs");
      expect((await buildPage(name)) === html, `site/${name}/index.html is stale: run \`npm run build:site\``).toBe(true);
    });
  });
}

describe("site pages: content", () => {
  it("verify: says that nothing is uploaded, and offers the checks, including approvers", () => {
    const html = readFileSync(SITE + "verify/index.html", "utf8");
    expect(html).toContain("Nothing is uploaded");
    for (const id of ["expect-key", "known-head", "req-rekor", "req-rfc3161", "require-full", "max-delay", "expect-until", "approvers", "webauthn-origins", "require-signed"]) {
      expect(html).toContain(`id="${id}"`);
    }
  });

  it("approve: asks for a user-verified passkey assertion over the digest, and has no backend", () => {
    const html = readFileSync(SITE + "approve/index.html", "utf8");
    expect(html).toContain("Nothing is uploaded");
    expect(html).toContain("navigator.credentials.get");
    expect(html).toMatch(/userVerification:"required"/);
    expect(html).not.toMatch(/<form[^>]+action=/);
  });
});

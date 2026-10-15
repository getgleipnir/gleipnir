import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

describe("browser compatibility of the verifier core", () => {
  it("imports no Node built-ins and uses no Node globals outside the CLI", () => {
    for (const f of readdirSync(SRC, { recursive: true }) as string[]) {
      if (!f.endsWith(".ts") || f === "cli.ts") continue;
      const text = readFileSync(SRC + f, "utf8");
      expect(text, f).not.toMatch(/from\s+["']node:|require\(|\bBuffer\b|\bprocess\.|import\.meta/);
      const imports = [...text.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1]!);
      for (const spec of imports) {
        expect(spec.startsWith(".") || spec.startsWith("@noble/") || spec === "fflate", `${f} imports ${spec}`).toBe(true);
      }
    }
  });
});

import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@getgleipnir/verify/mandate": fileURLToPath(new URL("./packages/verify/src/mandate.ts", import.meta.url)),
      "@getgleipnir/verify": fileURLToPath(new URL("./packages/verify/src/index.ts", import.meta.url)),
      "@getgleipnir/sdk": fileURLToPath(new URL("./packages/sdk/src/index.ts", import.meta.url)),
    },
  },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
    testTimeout: 30000,
  },
});

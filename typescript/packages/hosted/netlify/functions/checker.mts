// Netlify Functions v2 entry for the SANDBOX hosted checker. All logic lives in src/app.ts.
import { getStore } from "@netlify/blobs";
import { handle } from "../../src/app.js";
import { BlobsKV } from "../../src/kv.js";

export default async (req: Request, context: { ip?: string }): Promise<Response> => {
  const kv = new BlobsKV(getStore({ name: "gleipnir-sandbox-checker", consistency: "strong" }));
  return handle(req, {
    kv,
    ip: context?.ip,
    env: {
      ADMIN_TOKEN: process.env.ADMIN_TOKEN,
      MASTER_KEY: process.env.MASTER_KEY,
      ALLOW_ORIGINS: process.env.ALLOW_ORIGINS,
      RATE_LIMIT_PER_MIN: process.env.RATE_LIMIT_PER_MIN,
    },
  });
};

export const config = {
  path: ["/v1", "/v1/*", "/t/*"],
};

/**
 * Minimal GitHub webhook server using only node:http.
 * No Express or other framework needed.
 *
 * Usage:
 *   GITHUB_WEBHOOK_SECRET=mysecret npx tsx examples/github-webhook.ts
 *
 * Then configure your GitHub repo webhook to point at http://<host>:3900/
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { WebhookHandler, BundleEmitter, GitHubProvider, buildImportBundle, postImportBundle } from "../src/index.js";

const secret = process.env.GITHUB_WEBHOOK_SECRET;

const handler = new WebhookHandler([
  new GitHubProvider({ secret }),
]);

const emitter = new BundleEmitter({
  defaultRiskTier: "medium",
  riskLabels: {
    "security": "critical",
    "bug": "high",
    "enhancement": "low",
  },
  riskPaths: {
    critical: ["src/auth/", "src/crypto/"],
    high: ["src/api/", "migrations/"],
  },
});

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "text/plain" });
    res.end("Method Not Allowed");
    return;
  }

  try {
    const body = await readBody(req);
    const headers: Record<string, string> = {};
    for (const [key, val] of Object.entries(req.headers)) {
      if (typeof val === "string") headers[key] = val;
    }

    const event = await handler.handleRequest(headers, body);
    const bundle = emitter.fromEvent(event);

    console.log("Bundle created:", JSON.stringify(bundle, null, 2));

    const baseUrl = process.env.GUARDSPINE_BASE_URL;
    if (baseUrl) {
      const importBundle = await buildImportBundle(bundle);
      const result = await postImportBundle(importBundle, {
        baseUrl,
        token: process.env.GUARDSPINE_API_TOKEN,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ bundle: importBundle, importResult: result }));
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(bundle));
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal error";
    console.error("Webhook error:", message);
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: message }));
  }
});

const port = Number(process.env.PORT) || 3900;
server.listen(port, () => {
  console.log(`GuardSpine webhook listener on port ${port}`);
});

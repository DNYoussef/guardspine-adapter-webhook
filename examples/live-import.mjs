import { createServer } from "node:http";
import {
  WebhookHandler,
  BundleEmitter,
  GitHubProvider,
  buildImportBundle,
  postImportBundle,
} from "../dist/index.js";

const secret = process.env.GITHUB_WEBHOOK_SECRET;
const baseUrl = process.env.GUARDSPINE_BASE_URL;

const handler = new WebhookHandler([
  new GitHubProvider({ secret }),
]);

const emitter = new BundleEmitter({
  defaultRiskTier: "medium",
  riskLabels: {
    security: "critical",
    bug: "high",
  },
  riskPaths: {
    critical: ["src/auth/"],
  },
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = createServer(async (req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "text/plain" });
    res.end("Method Not Allowed");
    return;
  }

  try {
    const body = await readBody(req);
    const headers = {};
    for (const [key, val] of Object.entries(req.headers)) {
      if (typeof val === "string") headers[key] = val;
    }

    const event = await handler.handleRequest(headers, body);
    const bundle = emitter.fromEvent(event);

    if (baseUrl) {
      const importBundle = await buildImportBundle(bundle);
      if (process.env.DEBUG_GUARDSPINE_IMPORT) {
        console.log("import hash_chain[0]", importBundle.immutability_proof?.hash_chain?.[0]);
      }
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
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: message }));
  }
});

const port = Number(process.env.PORT) || 3901;
server.listen(port, () => {
  console.log(`GuardSpine live import adapter on port ${port}`);
});

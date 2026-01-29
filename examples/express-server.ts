/**
 * Example using Express (if you already have it in your project).
 * This file is for illustration only -- Express is NOT a dependency.
 *
 * Usage:
 *   npm install express @types/express
 *   GITHUB_WEBHOOK_SECRET=mysecret npx tsx examples/express-server.ts
 */

// @ts-expect-error -- express is not in devDependencies on purpose
import express from "express";
import {
  WebhookHandler,
  BundleEmitter,
  GitHubProvider,
  GitLabProvider,
  GenericProvider,
} from "../src/index.js";

const app = express();
app.use(express.text({ type: "*/*" }));

const handler = new WebhookHandler([
  new GitHubProvider({ secret: process.env.GITHUB_WEBHOOK_SECRET }),
  new GitLabProvider({ secretToken: process.env.GITLAB_SECRET_TOKEN }),
  new GenericProvider(),
]);

const emitter = new BundleEmitter({
  defaultRiskTier: "medium",
  riskLabels: { security: "critical", bug: "high" },
  riskPaths: { critical: ["src/auth/"] },
});

app.post("/webhook", async (req: { headers: Record<string, string>; body: string }, res: { json: (v: unknown) => void; status: (n: number) => { json: (v: unknown) => void } }) => {
  try {
    const event = await handler.handleRequest(req.headers, req.body);
    const bundle = emitter.fromEvent(event);
    res.json(bundle);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal error";
    res.status(400).json({ error: message });
  }
});

const port = Number(process.env.PORT) || 3900;
app.listen(port, () => {
  console.log(`GuardSpine Express webhook on port ${port}`);
});

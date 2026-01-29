import { createHmac, timingSafeEqual } from "node:crypto";
import type { WebhookEvent, WebhookProvider } from "../types.js";

export interface GitHubProviderOptions {
  /** Webhook secret for HMAC-SHA256 signature validation. Optional. */
  secret?: string;
}

/**
 * GitHub webhook provider.
 * Handles: pull_request, push, check_run events.
 * Validates X-Hub-Signature-256 when a secret is configured.
 */
export class GitHubProvider implements WebhookProvider {
  readonly name = "github";
  private readonly secret: string | undefined;

  constructor(options: GitHubProviderOptions = {}) {
    this.secret = options.secret;
  }

  matches(headers: Record<string, string>): boolean {
    return "x-github-event" in headers;
  }

  async validate(headers: Record<string, string>, body: string): Promise<void> {
    if (!this.secret) return;

    const signature = headers["x-hub-signature-256"];
    if (!signature) {
      throw new Error("Missing X-Hub-Signature-256 header");
    }

    const expected =
      "sha256=" +
      createHmac("sha256", this.secret).update(body, "utf8").digest("hex");

    const sigBuf = Buffer.from(signature, "utf8");
    const expBuf = Buffer.from(expected, "utf8");

    if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
      throw new Error("Signature mismatch");
    }
  }

  async parse(
    headers: Record<string, string>,
    body: string
  ): Promise<WebhookEvent> {
    const rawEventType = headers["x-github-event"] ?? "unknown";
    const payload = JSON.parse(body) as Record<string, unknown>;

    const eventType = normalizeEventType(rawEventType);
    const repo = extractString(payload, "repository.full_name") ?? "unknown/unknown";

    const event: WebhookEvent = {
      provider: "github",
      eventType,
      rawEventType,
      repo,
      labels: [],
      changedFiles: [],
      timestamp: new Date().toISOString(),
      rawPayload: payload,
    };

    if (rawEventType === "pull_request") {
      const pr = payload.pull_request as Record<string, unknown> | undefined;
      if (pr) {
        event.prNumber = pr.number as number | undefined;
        event.sha = extractString(pr, "head.sha");
        event.diffUrl = pr.diff_url as string | undefined;
        event.author = extractString(pr, "user.login");
        event.action = payload.action as string | undefined;
        const rawLabels = pr.labels as Array<{ name: string }> | undefined;
        if (Array.isArray(rawLabels)) {
          event.labels = rawLabels.map((l) => l.name);
        }
      }
    } else if (rawEventType === "push") {
      event.ref = payload.ref as string | undefined;
      event.sha = payload.after as string | undefined;
      event.diffUrl = payload.compare as string | undefined;
      event.author = extractString(payload, "pusher.name");
      const commits = payload.commits as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(commits)) {
        const files = new Set<string>();
        for (const c of commits) {
          for (const key of ["added", "removed", "modified"] as const) {
            const arr = c[key];
            if (Array.isArray(arr)) {
              for (const f of arr) {
                if (typeof f === "string") files.add(f);
              }
            }
          }
        }
        event.changedFiles = [...files];
      }
    } else if (rawEventType === "check_run") {
      const checkRun = payload.check_run as Record<string, unknown> | undefined;
      if (checkRun) {
        event.sha = extractString(checkRun, "head_sha");
        event.action = payload.action as string | undefined;
      }
    }

    return event;
  }
}

function normalizeEventType(
  raw: string
): WebhookEvent["eventType"] {
  switch (raw) {
    case "pull_request":
      return "pull_request";
    case "push":
      return "push";
    case "check_run":
      return "check_run";
    default:
      return "unknown";
  }
}

function extractString(obj: unknown, path: string): string | undefined {
  let current: unknown = obj;
  for (const key of path.split(".")) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" ? current : undefined;
}

import { timingSafeEqual } from "node:crypto";
import type { WebhookEvent, WebhookProvider } from "../types.js";

export interface GitLabProviderOptions {
  /** Secret token for X-Gitlab-Token validation. Optional. */
  secretToken?: string;
}

/**
 * GitLab webhook provider.
 * Handles: merge_request, push events.
 * Validates X-Gitlab-Token when a secret token is configured.
 */
export class GitLabProvider implements WebhookProvider {
  readonly name = "gitlab";
  private readonly secretToken: string | undefined;

  constructor(options: GitLabProviderOptions = {}) {
    this.secretToken = options.secretToken;
  }

  matches(headers: Record<string, string>): boolean {
    return "x-gitlab-event" in headers;
  }

  async validate(headers: Record<string, string>, _body: string): Promise<void> {
    if (!this.secretToken) return;

    const token = headers["x-gitlab-token"];
    if (!token) {
      throw new Error("Missing X-Gitlab-Token header");
    }

    const tokenBuf = Buffer.from(token, "utf8");
    const expectedBuf = Buffer.from(this.secretToken, "utf8");

    if (
      tokenBuf.length !== expectedBuf.length ||
      !timingSafeEqual(tokenBuf, expectedBuf)
    ) {
      throw new Error("Token mismatch");
    }
  }

  async parse(
    headers: Record<string, string>,
    body: string
  ): Promise<WebhookEvent> {
    const rawEventType = headers["x-gitlab-event"] ?? "unknown";
    const payload = JSON.parse(body) as Record<string, unknown>;

    const eventType = normalizeEventType(rawEventType);
    const project = payload.project as Record<string, unknown> | undefined;
    const repo = (project?.path_with_namespace as string) ?? "unknown/unknown";

    const event: WebhookEvent = {
      provider: "gitlab",
      eventType,
      rawEventType,
      repo,
      labels: [],
      changedFiles: [],
      timestamp: new Date().toISOString(),
      rawPayload: payload,
    };

    if (eventType === "merge_request") {
      const attrs = payload.object_attributes as Record<string, unknown> | undefined;
      if (attrs) {
        event.prNumber = attrs.iid as number | undefined;
        event.sha = attrs.last_commit
          ? ((attrs.last_commit as Record<string, unknown>).id as string)
          : undefined;
        event.diffUrl = attrs.url as string | undefined;
        event.author = extractString(payload, "user.username");
        event.action = attrs.action as string | undefined;
        const rawLabels = attrs.labels as Array<{ title: string }> | undefined;
        if (Array.isArray(rawLabels)) {
          event.labels = rawLabels.map((l) => l.title);
        }
      }
    } else if (eventType === "push") {
      event.ref = payload.ref as string | undefined;
      event.sha = payload.after as string | undefined;
      event.author = extractString(payload, "user_username") ?? extractString(payload, "user_name");
      const commits = payload.commits as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(commits)) {
        event.changedFiles = collectChangedFiles(commits);
      }
    }

    return event;
  }
}

/**
 * Collect unique changed file paths from an array of commit objects.
 * Merges "added", "removed", and "modified" arrays across all commits.
 */
function collectChangedFiles(commits: Array<Record<string, unknown>>): string[] {
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
  return [...files];
}

/**
 * Map a raw GitLab event type string to a normalized WebhookEvent eventType.
 * GitLab uses human-readable event names (e.g. "Merge Request Hook", "Push Hook").
 * Returns "unknown" for any unrecognized event type.
 *
 * @param raw - The raw event type string from the X-Gitlab-Event header.
 */
function normalizeEventType(
  raw: string
): WebhookEvent["eventType"] {
  const lower = raw.toLowerCase();
  if (lower.includes("merge request")) return "merge_request";
  if (lower.includes("push")) return "push";
  return "unknown";
}

/**
 * Safely extract a nested string property from an object using a dot-separated path.
 * Returns undefined if the path does not resolve to a string value.
 *
 * @param obj - The root object to traverse.
 * @param path - Dot-separated property path (e.g. "user.username").
 */
function extractString(obj: unknown, path: string): string | undefined {
  if (obj == null || typeof obj !== "object") return undefined;
  let current: unknown = obj;
  for (const key of path.split(".")) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" ? current : undefined;
}

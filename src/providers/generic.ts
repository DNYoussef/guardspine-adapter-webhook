import type { WebhookEvent, WebhookProvider } from "../types.js";

/**
 * Generic webhook provider -- pass-through for custom webhook sources.
 * Always matches (use as the last provider in the chain).
 * No signature validation.
 */
export class GenericProvider implements WebhookProvider {
  readonly name = "generic";

  matches(_headers: Record<string, string>): boolean {
    return true;
  }

  async validate(
    _headers: Record<string, string>,
    _body: string
  ): Promise<void> {
    // No validation for generic webhooks
  }

  async parse(
    _headers: Record<string, string>,
    body: string
  ): Promise<WebhookEvent> {
    const payload = JSON.parse(body) as Record<string, unknown>;

    return {
      provider: "generic",
      eventType: "unknown",
      rawEventType: (payload.event_type as string) ?? "unknown",
      repo: (payload.repo as string) ?? (payload.repository as string) ?? "unknown",
      prNumber: payload.pr_number as number | undefined,
      ref: payload.ref as string | undefined,
      sha: payload.sha as string | undefined,
      diffUrl: payload.diff_url as string | undefined,
      author: payload.author as string | undefined,
      labels: Array.isArray(payload.labels)
        ? (payload.labels as string[])
        : [],
      changedFiles: Array.isArray(payload.changed_files)
        ? (payload.changed_files as string[])
        : [],
      action: payload.action as string | undefined,
      timestamp: new Date().toISOString(),
      rawPayload: payload,
    };
  }
}

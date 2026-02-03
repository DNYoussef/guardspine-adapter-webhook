import type { WebhookEvent, WebhookProvider } from "../types.js";

export interface GenericProviderOptions {
  /**
   * When true, the provider will match any request that no other provider handles.
   * Defaults to false -- GenericProvider must be explicitly opted-in.
   */
  enabled?: boolean;
}

/**
 * Generic webhook provider -- pass-through for custom webhook sources.
 * Disabled by default; set `{ enabled: true }` to use as a catch-all fallback.
 * No signature validation.
 */
export class GenericProvider implements WebhookProvider {
  readonly name = "generic";
  private readonly enabled: boolean;

  constructor(options: GenericProviderOptions = {}) {
    this.enabled = options.enabled ?? false;
  }

  matches(_headers: Record<string, string>): boolean {
    if (!this.enabled) {
      return false;
    }
    console.warn(
      "GenericProvider matched a webhook request. This provider performs no signature validation. " +
      "Ensure this is intentional."
    );
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
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(body) as Record<string, unknown>;
    } catch {
      throw new Error("GenericProvider: request body is not valid JSON");
    }

    if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("GenericProvider: request body must be a JSON object");
    }

    return {
      provider: "generic",
      eventType: "unknown",
      rawEventType: typeof payload.event_type === "string" ? payload.event_type : "unknown",
      repo: typeof payload.repo === "string"
        ? payload.repo
        : typeof payload.repository === "string"
          ? payload.repository
          : "unknown",
      prNumber: typeof payload.pr_number === "number" ? payload.pr_number : undefined,
      ref: typeof payload.ref === "string" ? payload.ref : undefined,
      sha: typeof payload.sha === "string" ? payload.sha : undefined,
      diffUrl: typeof payload.diff_url === "string" ? payload.diff_url : undefined,
      author: typeof payload.author === "string" ? payload.author : undefined,
      labels: Array.isArray(payload.labels)
        ? (payload.labels as unknown[]).filter((l): l is string => typeof l === "string")
        : [],
      changedFiles: Array.isArray(payload.changed_files)
        ? (payload.changed_files as unknown[]).filter((f): f is string => typeof f === "string")
        : [],
      action: typeof payload.action === "string" ? payload.action : undefined,
      timestamp: new Date().toISOString(),
      rawPayload: payload,
    };
  }
}

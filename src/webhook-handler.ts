import type { WebhookEvent, WebhookProvider } from "./types.js";

/**
 * Error thrown when no provider matches the incoming request.
 */
export class NoMatchingProviderError extends Error {
  constructor() {
    super("No webhook provider matched the incoming request headers");
    this.name = "NoMatchingProviderError";
  }
}

/**
 * Error thrown when webhook signature validation fails.
 */
export class SignatureValidationError extends Error {
  constructor(provider: string, reason: string) {
    super(`Signature validation failed for provider "${provider}": ${reason}`);
    this.name = "SignatureValidationError";
  }
}

/**
 * Handles incoming webhook requests by delegating to the appropriate provider.
 *
 * Usage:
 *   const handler = new WebhookHandler([new GitHubProvider({ secret })]);
 *   const event = await handler.handleRequest(headers, body);
 */
export class WebhookHandler {
  private readonly providers: WebhookProvider[];

  constructor(providers: WebhookProvider[]) {
    if (providers.length === 0) {
      throw new Error("At least one WebhookProvider is required");
    }
    this.providers = providers;
  }

  /**
   * Process an incoming webhook request.
   *
   * 1. Finds the first provider whose matches() returns true.
   * 2. Validates the signature via the provider.
   * 3. Parses the body into a normalized WebhookEvent.
   *
   * @param headers - Lowercased header key-value pairs
   * @param body - Raw request body as a string
   * @returns Normalized WebhookEvent
   * @throws NoMatchingProviderError if no provider matches
   * @throws SignatureValidationError if validation fails
   */
  async handleRequest(
    headers: Record<string, string>,
    body: string
  ): Promise<WebhookEvent> {
    // Normalize header keys to lowercase
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      normalized[key.toLowerCase()] = value;
    }

    const provider = this.providers.find((p) => p.matches(normalized));
    if (!provider) {
      throw new NoMatchingProviderError();
    }

    try {
      await provider.validate(normalized, body);
    } catch (err: unknown) {
      if (err instanceof SignatureValidationError) {
        throw err;
      }
      const message = err instanceof Error ? err.message : String(err);
      throw new SignatureValidationError(provider.name, message);
    }

    return provider.parse(normalized, body);
  }
}

# @guardspine/adapter-webhook

Universal webhook adapter that converts GitHub, GitLab, Bitbucket, or custom webhook payloads into GuardSpine evidence bundles. Zero runtime dependencies.

## Install

```bash
npm install @guardspine/adapter-webhook
```

Optional: install `@guardspine/kernel` for cryptographic bundle sealing.

## Quick Start (GitHub Webhook)

```typescript
import {
  WebhookHandler,
  BundleEmitter,
  GitHubProvider,
} from "@guardspine/adapter-webhook";

const handler = new WebhookHandler([
  new GitHubProvider({ secret: process.env.GITHUB_WEBHOOK_SECRET }),
]);

const emitter = new BundleEmitter({
  defaultRiskTier: "medium",
  riskLabels: { security: "critical", bug: "high" },
  riskPaths: { critical: ["src/auth/", "src/crypto/"] },
});

// In your HTTP handler:
const event = await handler.handleRequest(headers, body);
const bundle = emitter.fromEvent(event);
// bundle is now a GuardSpine EmittedBundle ready for ingestion
```

See `examples/github-webhook.ts` for a complete node:http server.

## Providers

| Provider | Class | Header Detection | Signature |
|----------|-------|-----------------|-----------|
| GitHub | `GitHubProvider` | `x-github-event` | HMAC-SHA256 (`x-hub-signature-256`) |
| GitLab | `GitLabProvider` | `x-gitlab-event` | Token match (`x-gitlab-token`) |
| Generic | `GenericProvider` | Always matches | None |

Register providers in priority order. The first matching provider handles the request. Put `GenericProvider` last as a catch-all.

```typescript
const handler = new WebhookHandler([
  new GitHubProvider({ secret: "..." }),
  new GitLabProvider({ secretToken: "..." }),
  new GenericProvider(), // catch-all, always last
]);
```

## Custom Provider

Implement the `WebhookProvider` interface:

```typescript
import type { WebhookProvider, WebhookEvent } from "@guardspine/adapter-webhook";

class BitbucketProvider implements WebhookProvider {
  name = "bitbucket";

  matches(headers: Record<string, string>): boolean {
    return "x-event-key" in headers;
  }

  async validate(headers: Record<string, string>, body: string): Promise<void> {
    // Your validation logic
  }

  async parse(headers: Record<string, string>, body: string): Promise<WebhookEvent> {
    const payload = JSON.parse(body);
    return {
      provider: "bitbucket",
      eventType: "pull_request",
      rawEventType: headers["x-event-key"],
      repo: payload.repository.full_name,
      // ... fill remaining fields
      labels: [],
      changedFiles: [],
      timestamp: new Date().toISOString(),
      rawPayload: payload,
    };
  }
}
```

## Risk Tier Inference

The `BundleEmitter` infers risk tiers in this order:

1. **Labels** -- matched via `riskLabels` config (first match wins)
2. **File paths** -- matched via `riskPaths` config (prefix match)
3. **Default** -- falls back to `defaultRiskTier` (default: `"unknown"`)

## Bundle Sealing

If `@guardspine/kernel` is installed, call `sealBundle()` for cryptographic sealing:

```typescript
const bundle = emitter.fromEvent(event);
const sealed = await emitter.sealBundle(bundle);
// sealed.sealed === true if kernel was available
```

## Backend Import (v0.2.0)

To post bundles to the GuardSpine backend import endpoint:

```typescript
import { buildImportBundle, postImportBundle } from "@guardspine/adapter-webhook";

const bundle = emitter.fromEvent(event);
const importBundle = await buildImportBundle(bundle);
const result = await postImportBundle(importBundle, {
  baseUrl: "http://localhost:8000",
  token: process.env.GUARDSPINE_API_TOKEN,
});
```

`buildImportBundle()` requires `@guardspine/kernel` to compute the hash chain
and immutability proof. If the kernel is missing, it throws.

## API

### WebhookHandler

- `constructor(providers: WebhookProvider[])` -- at least one provider required
- `handleRequest(headers, body): Promise<WebhookEvent>` -- parse and validate

### BundleEmitter

- `constructor(config?: BundleEmitterConfig)` -- optional risk configuration
- `fromEvent(event: WebhookEvent): EmittedBundle` -- create evidence bundle
- `sealBundle(bundle: EmittedBundle): Promise<EmittedBundle>` -- seal with kernel

### Errors

- `NoMatchingProviderError` -- no provider matched the request headers
- `SignatureValidationError` -- webhook signature/token validation failed

## Development

```bash
npm install
npm test
npm run build
```

## License

Apache-2.0

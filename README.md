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

## Bundle Types

This adapter produces two bundle types:

| Type | Description | Use Case |
|------|-------------|----------|
| `EmittedBundle` | Pre-seal format with `kind`, `summary`, `contentHash` | Intermediate processing |
| `ImportBundle` | v0.2.0 spec format with `content_type`, `immutability_proof` | Backend ingestion |

**Important**: `EmittedBundle` is NOT spec-compliant. Use `buildImportBundle()` to convert
to v0.2.0 format before sending to the backend.

## Bundle Sealing

Sealing requires `@guardspine/kernel`:

```typescript
const bundle = emitter.fromEvent(event);

// Option 1: Seal EmittedBundle (informational only, not spec-compliant)
const sealed = await emitter.sealBundle(bundle);

// Option 2: Build spec-compliant ImportBundle (recommended)
const importBundle = await buildImportBundle(bundle);  // Requires kernel
```

**Warning**: `sealBundle()` fails hard if the kernel is missing or sealing fails.

## Backend Import (v0.2.x)

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

### Optional PII-Shield Sanitization

`buildImportBundle()` accepts an optional sanitizer to redact payload content before sealing:

```typescript
import { buildImportBundle, PIIShieldSanitizer } from "@guardspine/adapter-webhook";

const sanitizer = new PIIShieldSanitizer({
  endpoint: process.env.PII_SHIELD_ENDPOINT!,
  apiKey: process.env.PII_SHIELD_API_KEY,
});

const importBundle = await buildImportBundle(bundle, {
  sanitizer,
  saltFingerprint: "sha256:1a2b3c4d",
});
```

When enabled, bundles include a top-level `sanitization` attestation summary
compatible with GuardSpine spec v0.2.1.

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

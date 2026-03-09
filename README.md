# @guardspine/adapter-webhook

Universal webhook adapter that converts GitHub, GitLab, or custom webhook payloads into GuardSpine evidence bundles. Seals bundles cryptographically via `@guardspine/kernel` (TypeScript).

Part of the [GuardSpine](https://guardspine.ai) open-core ecosystem. Apache-2.0.

## How it works

```
Webhook POST
    |
    v
WebhookHandler -- picks first matching provider
    |
    v
Provider.validate() -- HMAC-SHA256 (GitHub) or token match (GitLab)
Provider.parse()    -- normalizes payload into WebhookEvent
    |
    v
BundleEmitter.fromEvent() -- builds EmittedBundle with risk tier, evidence items, SHA-256 hashes
    |
    v
BundleEmitter.sealBundle()    -- seals via @guardspine/kernel sealBundle() (adds immutability_proof)
  or buildImportBundle()      -- builds spec-compliant ImportBundle, seals, optionally sanitizes
    |
    v
postImportBundle() -- POST to /api/v1/bundles/import
```

## Why the TypeScript kernel

This adapter uses `@guardspine/kernel` (TypeScript) for `sealBundle()`. The TS kernel is the canonical implementation for TypeScript projects -- it computes the SHA-256 hash chain (`sequence|item_id|content_type|content_hash|previous_hash`) and returns the `immutability_proof` with `hash_chain` and `root_hash`. TypeScript consumers import it directly; there is no subprocess or FFI overhead.

## Install

```bash
npm install @guardspine/adapter-webhook @guardspine/kernel
```

`@guardspine/kernel` is a peer dependency (optional at the type level, but required at runtime for sealing and import bundle creation).

## Quick start

```typescript
import {
  WebhookHandler,
  BundleEmitter,
  GitHubProvider,
  buildImportBundle,
  postImportBundle,
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

// Option A: Seal the EmittedBundle directly
const sealed = await emitter.sealBundle(bundle);

// Option B: Build a spec-compliant ImportBundle and POST it
const importBundle = await buildImportBundle(bundle);
const result = await postImportBundle(importBundle, {
  baseUrl: "https://your-guardspine-backend",
  token: process.env.GUARDSPINE_API_TOKEN,
});
```

## Providers

| Provider | Class | Header detection | Signature validation |
|----------|-------|-----------------|---------------------|
| GitHub | `GitHubProvider` | `x-github-event` | HMAC-SHA256 via `x-hub-signature-256` |
| GitLab | `GitLabProvider` | `x-gitlab-event` | Token match via `x-gitlab-token` |
| Generic | `GenericProvider` | Catch-all (disabled by default) | None |

Register providers in priority order. The first provider whose `matches()` returns true handles the request.

```typescript
const handler = new WebhookHandler([
  new GitHubProvider({ secret: "..." }),
  new GitLabProvider({ secretToken: "..." }),
  new GenericProvider({ enabled: true }), // catch-all, must opt in
]);
```

`GenericProvider` is disabled by default. Pass `{ enabled: true }` to use it. It performs no signature validation and logs a warning on every match.

### GitHub events handled

`pull_request`, `push`, `check_run`. Extracts PR number, SHA, diff URL, author, labels, and changed files.

### GitLab events handled

`Merge Request Hook` (normalized to `merge_request`), `Push Hook` (normalized to `push`). Extracts MR IID, SHA, diff URL, author, labels, and changed files.

### Custom providers

Implement the `WebhookProvider` interface:

```typescript
import type { WebhookProvider, WebhookEvent } from "@guardspine/adapter-webhook";

class BitbucketProvider implements WebhookProvider {
  name = "bitbucket";

  matches(headers: Record<string, string>): boolean {
    return "x-event-key" in headers;
  }

  async validate(headers: Record<string, string>, body: string): Promise<void> {
    // Your signature validation
  }

  async parse(headers: Record<string, string>, body: string): Promise<WebhookEvent> {
    const payload = JSON.parse(body);
    return {
      provider: "bitbucket",
      eventType: "pull_request",
      rawEventType: headers["x-event-key"],
      repo: payload.repository.full_name,
      labels: [],
      changedFiles: [],
      timestamp: new Date().toISOString(),
      rawPayload: payload,
    };
  }
}
```

## Risk tier inference

`BundleEmitter` infers risk tiers in priority order:

1. **Labels** -- first match in `riskLabels` config wins
2. **File paths** -- prefix match against `riskPaths` config
3. **Default** -- falls back to `defaultRiskTier` (default: `"unknown"`)

## Bundle types

| Type | Purpose | Spec-compliant |
|------|---------|---------------|
| `EmittedBundle` | Intermediate format with `kind`, `summary`, `contentHash` | No |
| `ImportBundle` | v0.2.0/v0.2.1 format with `content_type`, `immutability_proof` | Yes |

Use `buildImportBundle()` to convert an `EmittedBundle` into spec-compliant `ImportBundle` format before sending to the backend. Both `sealBundle()` and `buildImportBundle()` call `kernel.sealBundle()` internally.

## Evidence items

Each bundle contains evidence items extracted from the webhook payload:

| Kind | When created | Content |
|------|-------------|---------|
| `diff` | Event has a `diffUrl` | Canonical JSON of the raw payload |
| `metadata` | Always | Repo, author, SHA, labels, changed files |
| `check_result` | `check_run` events only | Canonical JSON of the check run payload |

All content is hashed with SHA-256 (prefixed `sha256:<hex>`) before sealing.

## Bundle sealing

Both sealing paths fail hard if the kernel is missing or sealing fails. There is no silent fallback to unsealed bundles.

```typescript
// Direct seal (adds immutability_proof to EmittedBundle)
const sealed = await emitter.sealBundle(bundle);

// Import bundle path (builds spec-compliant format + seals)
const importBundle = await buildImportBundle(bundle);
```

## PII sanitization (optional)

`PIIShieldSanitizer` runs PII-Shield via WASM in-process (no external server). Sanitization happens before SHA-256 hashing, so secrets never enter the hash chain.

```typescript
import { buildImportBundle, PIIShieldSanitizer } from "@guardspine/adapter-webhook";

const sanitizer = new PIIShieldSanitizer({});
const importBundle = await buildImportBundle(bundle, {
  sanitizer,
  saltFingerprint: "sha256:your-org-fingerprint",
});
```

When sanitization is active, the bundle version is upgraded to `0.2.1` and includes a `sanitization` attestation with `input_hash`, `output_hash`, and redaction counts.

Sanitization also works with `sealBundle()` by passing a sanitizer as the second argument.

### Environment variables

| Variable | Description |
|----------|-------------|
| `PII_SALT` | HMAC salt for deterministic redaction tokens |
| `PII_SAFE_REGEX_LIST` | JSON array of `[{"pattern": "...", "name": "..."}]` to whitelist safe high-entropy strings |
| `PII_ENTROPY_THRESHOLD` | Shannon entropy threshold for secret detection (default: 4.5) |

## API reference

### WebhookHandler

- `constructor(providers: WebhookProvider[])` -- at least one provider required
- `handleRequest(headers, body): Promise<WebhookEvent>` -- validates and parses

### BundleEmitter

- `constructor(config?: BundleEmitterConfig)` -- optional risk tier configuration
- `fromEvent(event: WebhookEvent): EmittedBundle` -- build unsealed bundle
- `sealBundle(bundle: EmittedBundle, sanitizer?: BundleSanitizer): Promise<EmittedBundle>` -- seal with kernel

### Import functions

- `buildImportBundle(bundle, options?): Promise<ImportBundle>` -- build spec-compliant sealed bundle
- `postImportBundle(bundle, options): Promise<GuardSpineImportResponse>` -- POST to backend

### Errors

- `NoMatchingProviderError` -- no provider matched the request headers
- `SignatureValidationError` -- webhook signature/token validation failed

## Development

```bash
npm install
npm test          # vitest
npm run build     # tsc
```

Requires Node.js >= 20. Uses ES modules (`"type": "module"`).

## License

Apache-2.0

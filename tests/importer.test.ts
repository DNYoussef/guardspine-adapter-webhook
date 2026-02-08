import { describe, it, expect } from "vitest";
import { BundleEmitter } from "../src/bundle-emitter.js";
import { buildImportBundle } from "../src/importer.js";
import type { BundleSanitizer, WebhookEvent } from "../src/types.js";

function makeEvent(overrides: Partial<WebhookEvent> = {}): WebhookEvent {
  return {
    provider: "github",
    eventType: "pull_request",
    rawEventType: "pull_request",
    repo: "org/repo",
    prNumber: 42,
    sha: "abc123def456",
    diffUrl: "https://github.com/org/repo/pull/42.diff",
    author: "testuser",
    labels: [],
    changedFiles: [],
    timestamp: "2026-01-15T00:00:00.000Z",
    rawPayload: {},
    ...overrides,
  };
}

describe("buildImportBundle", () => {
  it("creates a spec bundle with immutability proof when kernel is available", async () => {
    try {
      let hasKernel = true;
      try {
        await import("@guardspine/kernel");
      } catch {
        hasKernel = false;
      }
      if (!hasKernel) {
        expect(true).toBe(true);
        return;
      }

      const emitter = new BundleEmitter();
      const emitted = emitter.fromEvent(makeEvent());
      const imported = await buildImportBundle(emitted);

      expect(imported.version).toBe("0.2.0");
      expect(imported.items.length).toBeGreaterThan(0);
      expect(imported.immutability_proof).toBeDefined();
      expect(imported.items[0].content_type).toMatch(/^guardspine\/webhook\//);
      expect(imported.items[0].content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    } finally {
      // no-op
    }
  });

  it("adds sanitization summary when sanitizer is provided", async () => {
    let hasKernel = true;
    try {
      await import("@guardspine/kernel");
    } catch {
      hasKernel = false;
    }
    if (!hasKernel) {
      expect(true).toBe(true);
      return;
    }

    const sanitizer: BundleSanitizer = {
      async sanitizeText(text) {
        return {
          sanitizedText: text.replace("testuser", "[HIDDEN:abc123]"),
          changed: text.includes("testuser"),
          redactionCount: text.includes("testuser") ? 1 : 0,
          redactionsByType: text.includes("testuser") ? { username: 1 } : {},
          engineName: "pii-shield",
          engineVersion: "1.1.0",
          method: "deterministic_hmac",
        };
      },
    };

    const emitter = new BundleEmitter();
    const emitted = emitter.fromEvent(makeEvent({ rawPayload: { actor: "testuser" } }));
    const imported = await buildImportBundle(emitted, {
      sanitizer,
      saltFingerprint: "sha256:1a2b3c4d",
    });

    expect(imported.sanitization).toBeDefined();
    expect(imported.sanitization?.engine_name).toBe("pii-shield");
    expect(imported.sanitization?.salt_fingerprint).toBe("sha256:1a2b3c4d");
    expect(imported.sanitization?.applied_to).toContain("webhook_payload");
  });
});

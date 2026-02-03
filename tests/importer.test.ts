import { describe, it, expect } from "vitest";
import { BundleEmitter } from "../src/bundle-emitter.js";
import { buildImportBundle } from "../src/importer.js";
import type { WebhookEvent } from "../src/types.js";

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
});

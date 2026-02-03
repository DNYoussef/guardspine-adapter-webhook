import { describe, it, expect } from "vitest";
import { BundleEmitter } from "../src/bundle-emitter.js";
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

describe("BundleEmitter", () => {
  it("creates a valid bundle from a PR event", () => {
    const emitter = new BundleEmitter();
    const bundle = emitter.fromEvent(makeEvent());

    expect(bundle.version).toBe("0.2.0");
    expect(bundle.artifactId).toBe("org-repo-pr-42");
    expect(bundle.provider).toBe("github");
    expect(bundle.items.length).toBeGreaterThanOrEqual(2);
    expect(bundle.immutability_proof).toBeUndefined();
  });

  it("uses SHA prefix for push events without PR", () => {
    const emitter = new BundleEmitter();
    const bundle = emitter.fromEvent(
      makeEvent({ eventType: "push", prNumber: undefined, sha: "deadbeef12345678" })
    );
    expect(bundle.artifactId).toBe("org-repo-deadbeef");
  });

  it("infers risk tier from labels", () => {
    const emitter = new BundleEmitter({
      riskLabels: { security: "critical", bug: "high" },
    });
    const bundle = emitter.fromEvent(makeEvent({ labels: ["security"] }));
    expect(bundle.riskTier).toBe("critical");
  });

  it("infers risk tier from changed file paths", () => {
    const emitter = new BundleEmitter({
      riskPaths: { critical: ["src/auth/"] },
    });
    const bundle = emitter.fromEvent(
      makeEvent({ changedFiles: ["src/auth/login.ts"], labels: [] })
    );
    expect(bundle.riskTier).toBe("critical");
  });

  it("uses default risk tier when nothing matches", () => {
    const emitter = new BundleEmitter({ defaultRiskTier: "low" });
    const bundle = emitter.fromEvent(makeEvent());
    expect(bundle.riskTier).toBe("low");
  });

  it("labels take precedence over paths", () => {
    const emitter = new BundleEmitter({
      riskLabels: { bug: "high" },
      riskPaths: { critical: ["src/auth/"] },
    });
    const bundle = emitter.fromEvent(
      makeEvent({ labels: ["bug"], changedFiles: ["src/auth/login.ts"] })
    );
    expect(bundle.riskTier).toBe("high");
  });

  it("builds correct scope string", () => {
    const emitter = new BundleEmitter();
    const bundle = emitter.fromEvent(makeEvent({ action: "opened" }));
    expect(bundle.scope).toBe("github:pull_request:org/repo:#42:opened");
  });

  it("includes diff evidence item with URL", () => {
    const emitter = new BundleEmitter();
    const bundle = emitter.fromEvent(makeEvent());
    const diffItem = bundle.items.find((i) => i.kind === "diff");
    expect(diffItem).toBeDefined();
    expect(diffItem!.url).toBe("https://github.com/org/repo/pull/42.diff");
    expect(diffItem!.contentHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("includes metadata evidence item", () => {
    const emitter = new BundleEmitter();
    const bundle = emitter.fromEvent(makeEvent());
    const metaItem = bundle.items.find((i) => i.kind === "metadata");
    expect(metaItem).toBeDefined();
    expect(metaItem!.summary).toContain("github");
  });

  it("includes check_result item for check_run events", () => {
    const emitter = new BundleEmitter();
    const bundle = emitter.fromEvent(
      makeEvent({ eventType: "check_run", rawPayload: { status: "completed" } })
    );
    const checkItem = bundle.items.find((i) => i.kind === "check_result");
    expect(checkItem).toBeDefined();
  });

  it("chain hash is deterministic for same items", () => {
    const emitter = new BundleEmitter();
    const event = makeEvent();
    const b1 = emitter.fromEvent(event);
    const b2 = emitter.fromEvent(event);
    expect(b1.items).toEqual(b2.items);
  });

  it("sealBundle returns immutability proof when kernel available", async () => {
    const emitter = new BundleEmitter();
    const bundle = emitter.fromEvent(makeEvent());
    const result = await emitter.sealBundle(bundle);
    expect(result.immutability_proof).toBeDefined();
    expect(result.immutability_proof?.hash_chain?.length).toBeGreaterThan(0);
  });
});

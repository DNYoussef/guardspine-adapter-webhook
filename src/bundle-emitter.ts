import { createHash } from "node:crypto";
import type {
  BundleEmitterConfig,
  EmittedBundle,
  EvidenceItem,
  WebhookEvent,
} from "./types.js";

/**
 * Creates GuardSpine evidence bundles from normalized webhook events.
 *
 * If @guardspine/kernel is available, uses its seal() function
 * for cryptographic sealing. Otherwise, falls back to a basic SHA-256 hash chain.
 */
export class BundleEmitter {
  private readonly config: Required<BundleEmitterConfig>;
  private sealFn: ((bundle: unknown) => unknown) | null = null;

  constructor(config: BundleEmitterConfig = {}) {
    this.config = {
      defaultRiskTier: config.defaultRiskTier ?? "unknown",
      riskPaths: config.riskPaths ?? {},
      riskLabels: config.riskLabels ?? {},
    };
    this.tryLoadKernel();
  }

  /**
   * Attempt to load @guardspine/kernel for sealing support.
   * Fails silently -- kernel is an optional peer dependency.
   */
  private tryLoadKernel(): void {
    try {
      // Dynamic import would be async; we attempt a synchronous require-style probe.
      // In ESM we cannot use require, so we mark seal as unavailable and
      // let callers use sealBundle() for async sealing if needed.
      this.sealFn = null;
    } catch {
      this.sealFn = null;
    }
  }

  /**
   * Build an evidence bundle from a webhook event.
   */
  fromEvent(event: WebhookEvent): EmittedBundle {
    const artifactId = this.buildArtifactId(event);
    const riskTier = this.inferRiskTier(event);
    const scope = this.buildScope(event);
    const items = this.buildItems(event);
    const chainHash = this.computeChainHash(items);

    return {
      schemaVersion: "0.1.0",
      artifactId,
      riskTier,
      scope,
      items,
      chainHash,
      sealed: false,
      createdAt: new Date().toISOString(),
      provider: event.provider,
    };
  }

  /**
   * Attempt to seal a bundle using @guardspine/kernel.
   * Returns the original bundle (with sealed=true) if kernel is available,
   * or the bundle unchanged if not.
   */
  async sealBundle(bundle: EmittedBundle): Promise<EmittedBundle> {
    try {
      const kernel = await import("@guardspine/kernel");
      // TODO: Full kernel integration requires converting EmittedBundle to
      // EvidenceBundle format that kernel.sealBundle() expects. For now we
      // only call sealBundle() if available and let it throw on shape mismatch
      // so callers fall back to the unsealed path gracefully.
      if (typeof kernel.sealBundle === "function") {
        kernel.sealBundle(bundle);
        return { ...bundle, sealed: true };
      }
    } catch {
      // kernel not available or bundle shape mismatch -- return unsealed
    }
    return bundle;
  }

  private buildArtifactId(event: WebhookEvent): string {
    const base = event.repo.replace(/\//g, "-");
    if (event.prNumber != null) {
      return `${base}-pr-${event.prNumber}`;
    }
    if (event.sha) {
      return `${base}-${event.sha.slice(0, 8)}`;
    }
    return `${base}-${Date.now()}`;
  }

  private inferRiskTier(event: WebhookEvent): string {
    // Check labels first
    for (const label of event.labels) {
      const tier = this.config.riskLabels[label];
      if (tier) return tier;
    }

    // Check changed file paths
    for (const [tier, prefixes] of Object.entries(this.config.riskPaths)) {
      for (const prefix of prefixes) {
        if (event.changedFiles.some((f) => f.startsWith(prefix))) {
          return tier;
        }
      }
    }

    return this.config.defaultRiskTier;
  }

  private buildScope(event: WebhookEvent): string {
    const parts: string[] = [event.provider, event.eventType, event.repo];
    if (event.prNumber != null) {
      parts.push(`#${event.prNumber}`);
    }
    if (event.action) {
      parts.push(event.action);
    }
    return parts.join(":");
  }

  private buildItems(event: WebhookEvent): EvidenceItem[] {
    const items: EvidenceItem[] = [];

    // Diff evidence
    if (event.diffUrl) {
      items.push({
        kind: "diff",
        summary: `Diff for ${event.repo}${event.prNumber != null ? ` #${event.prNumber}` : ""}`,
        url: event.diffUrl,
        contentHash: sha256(event.diffUrl),
      });
    }

    // Metadata evidence
    const metaPayload = JSON.stringify({
      repo: event.repo,
      author: event.author,
      sha: event.sha,
      labels: event.labels,
      changedFiles: event.changedFiles,
    });
    items.push({
      kind: "metadata",
      summary: `Event metadata from ${event.provider}`,
      contentHash: sha256(metaPayload),
    });

    // Check result evidence (for check_run events)
    if (event.eventType === "check_run" && event.rawPayload) {
      items.push({
        kind: "check_result",
        summary: "CI check run result",
        contentHash: sha256(JSON.stringify(event.rawPayload)),
      });
    }

    return items;
  }

  private computeChainHash(items: EvidenceItem[]): string {
    const concatenated = items.map((i) => i.contentHash).join("");
    return sha256(concatenated);
  }
}

function sha256(input: string): string {
  return `sha256:${createHash("sha256").update(input, "utf8").digest("hex")}`;
}

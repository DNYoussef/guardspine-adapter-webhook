import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";
import type {
  BundleEmitterConfig,
  EmittedBundle,
  EvidenceItem,
  ImmutabilityProof,
  WebhookEvent,
} from "./types.js";

/**
 * Creates GuardSpine evidence bundles from normalized webhook events.
 *
 * Uses @guardspine/kernel sealBundle() for cryptographic sealing when available.
 * The kernel computes the hash chain (SHA-256 of sequence|item_id|content_type|content_hash|previous_hash).
 * When kernel is unavailable, the bundle is emitted without an immutability_proof.
 */
export class BundleEmitter {
  private readonly config: Required<BundleEmitterConfig>;

  constructor(config: BundleEmitterConfig = {}) {
    this.config = {
      defaultRiskTier: config.defaultRiskTier ?? "unknown",
      riskPaths: config.riskPaths ?? {},
      riskLabels: config.riskLabels ?? {},
    };
  }

  /**
   * Build an evidence bundle from a webhook event.
   * Returns an unsealed bundle. Call sealBundle() to add immutability_proof.
   */
  fromEvent(event: WebhookEvent): EmittedBundle {
    const artifactId = this.buildArtifactId(event);
    const riskTier = this.inferRiskTier(event);
    const scope = this.buildScope(event);
    const items = this.buildItems(event);

    return {
      bundle_id: randomUUID(),
      version: "0.2.0",
      artifactId,
      riskTier,
      scope,
      items,
      created_at: new Date().toISOString(),
      provider: event.provider,
    };
  }

  /**
   * Seal a bundle using @guardspine/kernel.
   * Returns the bundle with immutability_proof if kernel is available,
   * or the bundle unchanged if not.
   */
  async sealBundle(bundle: EmittedBundle): Promise<EmittedBundle> {
    let kernel: typeof import("@guardspine/kernel");
    try {
      kernel = await import("@guardspine/kernel");
    } catch {
      // @guardspine/kernel is an optional peer dependency -- return unsealed
      return bundle;
    }

    if (typeof kernel.sealBundle !== "function") {
      return bundle;
    }

    try {
      const sealed = kernel.sealBundle(bundle) as unknown as {
        items: EvidenceItem[];
        immutabilityProof: ImmutabilityProof;
      };
      return {
        ...bundle,
        items: sealed.items,
        immutability_proof: sealed.immutabilityProof,
      };
    } catch {
      // Bundle shape mismatch or sealing failure -- return without proof.
      // Callers can check for immutability_proof presence to detect this.
      return bundle;
    }
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

    // Diff evidence -- hash the raw payload (actual diff content), not just the URL
    if (event.diffUrl) {
      const diffContent = event.rawPayload
        ? JSON.stringify(event.rawPayload)
        : event.diffUrl;
      items.push({
        kind: "diff",
        summary: `Diff for ${event.repo}${event.prNumber != null ? ` #${event.prNumber}` : ""}`,
        url: event.diffUrl,
        content: diffContent,
        contentHash: sha256(diffContent),
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
      content: metaPayload,
      contentHash: sha256(metaPayload),
    });

    // Check result evidence (for check_run events)
    if (event.eventType === "check_run" && event.rawPayload) {
      const checkContent = JSON.stringify(event.rawPayload);
      items.push({
        kind: "check_result",
        summary: "CI check run result",
        content: checkContent,
        contentHash: sha256(checkContent),
      });
    }

    return items;
  }
}

/**
 * Compute a prefixed SHA-256 hex digest of the given input string.
 * This is a pure function with no side effects.
 *
 * @param input - The string to hash.
 * @returns A string in the format "sha256:<hex_digest>".
 */
function sha256(input: string): string {
  return `sha256:${createHash("sha256").update(input, "utf8").digest("hex")}`;
}

import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";
import type {
  BundleEmitterConfig,
  BundleSanitizer,
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
   *
   * SECURITY: This method now FAILS HARD if sealing cannot be performed.
   * An unsealed bundle provides no integrity guarantees and should not
   * be accepted by downstream systems.
   *
   * @throws Error if @guardspine/kernel is not installed
   * @throws Error if kernel.sealBundle is not available
   * @throws Error if sealing fails for any reason
   */
  async sealBundle(bundle: EmittedBundle, sanitizer?: BundleSanitizer): Promise<EmittedBundle> {
    let kernel: typeof import("@guardspine/kernel");
    try {
      kernel = await import("@guardspine/kernel");
    } catch (err) {
      // SECURITY: Fail hard - kernel is required for integrity guarantees
      throw new Error(
        "@guardspine/kernel is required for bundle sealing. " +
        "Install with: npm install @guardspine/kernel"
      );
    }

    if (typeof kernel.sealBundle !== "function") {
      // SECURITY: Fail hard - kernel must provide sealBundle
      throw new Error(
        "@guardspine/kernel.sealBundle is not available. " +
        "Ensure you have kernel version >= 0.2.0"
      );
    }

    try {
      // Sanitize items before sealing to prevent PII leaking into the
      // cryptographic data model (same pattern as buildImportBundle path).
      let items = bundle.items;
      if (sanitizer) {
        items = await Promise.all(
          items.map(async (item) => {
            const result = await sanitizer.sanitizeText(item.content, {
              inputFormat: "json",
              purpose: "webhook_payload",
            });
            if (result.changed) {
              return { ...item, content: result.sanitizedText, contentHash: sha256(result.sanitizedText) };
            }
            return item;
          })
        );
      }

      // Convert adapter-native items to canonical v0.2.0 item shape before sealing.
      // This ensures chain binding includes item_id/content_type semantics and avoids
      // leaking adapter-only fields into the cryptographic data model.
      const draft = {
        bundle_id: bundle.bundle_id,
        version: "0.2.0" as const,
        created_at: bundle.created_at,
        items: items.map((item, idx) => ({
          item_id: this.normalizeItemId(idx, item.kind),
          content_type: this.contentTypeForKind(item.kind),
          content: {
            kind: item.kind,
            summary: item.summary,
            url: item.url,
            content: item.content,
          },
        })),
        metadata: {
          artifact_id: bundle.artifactId,
          risk_tier: bundle.riskTier,
          scope: bundle.scope,
          provider: bundle.provider,
        },
      };

      const sealed = kernel.sealBundle(draft) as unknown as {
        immutabilityProof: ImmutabilityProof;
      };
      if (!sealed?.immutabilityProof) {
        throw new Error("Kernel sealing did not return immutability proof");
      }
      return {
        ...bundle,
        immutability_proof: sealed.immutabilityProof,
      };
    } catch (err) {
      // SECURITY: Fail hard - sealing errors must not be silenced
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Failed to seal bundle: ${message}. ` +
        "Bundle integrity cannot be guaranteed."
      );
    }
  }

  private normalizeItemId(index: number, kind: string): string {
    return `item-${index}-${kind}`;
  }

  private contentTypeForKind(kind: string): string {
    return `guardspine/webhook/${kind}`;
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
        ? canonicalJson(event.rawPayload)
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
    const metaPayload = canonicalJson({
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
      const checkContent = canonicalJson(event.rawPayload);
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

/**
 * Local canonical JSON implementation for pre-sealing content preparation.
 *
 * NOTE: This is used ONLY for building item content before sealBundle() is called.
 * The actual hash chain hashes are computed by @guardspine/kernel which has
 * its own RFC 8785-compliant implementation. This local version is kept for
 * backward compatibility when preparing content, but the kernel's implementation
 * is authoritative for all hash computations.
 *
 * TODO: Consider removing this once all callers use kernel directly.
 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

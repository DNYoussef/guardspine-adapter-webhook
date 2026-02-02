/**
 * Normalized webhook event from any provider.
 */
export interface WebhookEvent {
  /** Provider that produced the event (e.g. "github", "gitlab", "generic") */
  provider: string;
  /** Event type normalized across providers */
  eventType: "pull_request" | "push" | "check_run" | "merge_request" | "unknown";
  /** Raw event type string from the source */
  rawEventType: string;
  /** Repository full name (e.g. "org/repo") */
  repo: string;
  /** Pull/merge request number, if applicable */
  prNumber?: number;
  /** Git ref (branch or tag) */
  ref?: string;
  /** Commit SHA */
  sha?: string;
  /** URL to the diff or compare view */
  diffUrl?: string;
  /** Author login or username */
  author?: string;
  /** Labels attached to the PR/MR */
  labels: string[];
  /** Changed file paths, if available */
  changedFiles: string[];
  /** Action within the event (e.g. "opened", "synchronize") */
  action?: string;
  /** ISO8601 timestamp */
  timestamp: string;
  /** Raw payload (parsed JSON) */
  rawPayload: unknown;
}

/**
 * A webhook provider knows how to validate and parse events from a specific source.
 */
export interface WebhookProvider {
  /** Unique name for this provider */
  name: string;
  /**
   * Return true if this provider can handle the given request headers.
   */
  matches(headers: Record<string, string>): boolean;
  /**
   * Validate the webhook signature/token. Throws on failure.
   * Returns silently if validation passes or is not configured.
   */
  validate(headers: Record<string, string>, body: string): Promise<void>;
  /**
   * Parse the raw body + headers into a normalized WebhookEvent.
   */
  parse(headers: Record<string, string>, body: string): Promise<WebhookEvent>;
}

/**
 * Configuration for the BundleEmitter.
 */
export interface BundleEmitterConfig {
  /**
   * Default risk tier when none can be inferred.
   * @default "unknown"
   */
  defaultRiskTier?: string;
  /**
   * Path patterns that indicate high-risk changes.
   * Keys are tier names, values are glob-like path prefixes.
   */
  riskPaths?: Record<string, string[]>;
  /**
   * Label-to-risk-tier mapping.
   * Keys are label strings, values are tier names.
   */
  riskLabels?: Record<string, string>;
}

/**
 * An evidence item within a bundle (pre-seal, built by the adapter).
 */
export interface EvidenceItem {
  /** Type of evidence */
  kind: "diff" | "metadata" | "check_result";
  /** Short description */
  summary: string;
  /** URL to the source, if available */
  url?: string;
  /** The actual content that was hashed (used by kernel for chain computation) */
  content: string;
  /** SHA-256 hash of the content */
  contentHash: string;
}

/**
 * A chain link returned by kernel.sealBundle().
 */
export interface ChainLink {
  item_id: string;
  content_type: string;
  content_hash: string;
  previous_hash: string;
  sequence: number;
}

/**
 * The immutability proof returned by kernel.sealBundle().
 */
export interface ImmutabilityProof {
  hash_chain: ChainLink[];
  root_hash: string;
}

/**
 * An emitted evidence bundle ready for GuardSpine ingestion (v0.2.0).
 */
export interface EmittedBundle {
  /** Unique bundle identifier */
  bundle_id: string;
  /** Schema version */
  version: "0.2.0";
  /** Unique artifact identifier (repo + PR/ref) */
  artifactId: string;
  /** Inferred risk tier */
  riskTier: string;
  /** Scope description */
  scope: string;
  /** Evidence items (as returned by kernel.sealBundle) */
  items: EvidenceItem[];
  /** Cryptographic immutability proof from kernel (absent if kernel unavailable) */
  immutability_proof?: ImmutabilityProof;
  /** ISO8601 creation timestamp */
  created_at: string;
  /** Source provider name */
  provider: string;
}

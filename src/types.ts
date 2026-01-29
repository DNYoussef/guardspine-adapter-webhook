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
 * An evidence item within a bundle.
 */
export interface EvidenceItem {
  /** Type of evidence */
  kind: "diff" | "metadata" | "check_result";
  /** Short description */
  summary: string;
  /** URL to the source, if available */
  url?: string;
  /** SHA-256 hash of the content */
  contentHash: string;
}

/**
 * An emitted evidence bundle ready for GuardSpine ingestion.
 */
export interface EmittedBundle {
  /** Schema version */
  schemaVersion: "0.1.0";
  /** Unique artifact identifier (repo + PR/ref) */
  artifactId: string;
  /** Inferred risk tier */
  riskTier: string;
  /** Scope description */
  scope: string;
  /** Evidence items */
  items: EvidenceItem[];
  /** Hash chain: SHA-256 of all item hashes concatenated */
  chainHash: string;
  /** Whether the bundle was sealed with @guardspine/kernel */
  sealed: boolean;
  /** ISO8601 creation timestamp */
  createdAt: string;
  /** Source provider name */
  provider: string;
}

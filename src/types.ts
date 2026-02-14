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

export interface NormalizedEvidenceItem {
  item_id: string;
  content_type: string;
  content_hash: string;
  sequence: number;
  content: {
    kind: string;
    summary: string;
    url?: string;
    content: string;
  };
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
  items: EvidenceItem[] | NormalizedEvidenceItem[];
  /** Cryptographic immutability proof from kernel (absent if kernel unavailable) */
  immutability_proof?: ImmutabilityProof;
  /** ISO8601 creation timestamp */
  created_at: string;
  /** Source provider name */
  provider: string;
}

/**
 * Import bundle item (spec-compatible shape).
 */
export interface ImportBundleItem {
  item_id: string;
  content_type: string;
  content: unknown;
  content_hash?: string;
  sequence?: number;
}

/**
 * Import bundle payload (v0.2.0) for /api/v1/bundles/import.
 */
export interface ImportBundle {
  bundle_id: string;
  version: "0.2.0" | "0.2.1";
  created_at: string;
  items: ImportBundleItem[];
  immutability_proof?: ImmutabilityProof;
  sanitization?: SanitizationSummary;
  metadata?: Record<string, unknown>;
}

export interface GuardSpineImportOptions {
  baseUrl: string;
  token?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export interface GuardSpineImportResponse {
  ok: boolean;
  status: number;
  data?: unknown;
  error?: string;
}

export interface SanitizerRequest {
  inputFormat: "text" | "json" | "diff" | "markdown";
  purpose?: string;
  includeFindings?: boolean;
}

export interface SanitizerResult {
  sanitizedText: string;
  changed: boolean;
  redactionCount: number;
  redactionsByType: Record<string, number>;
  engineName?: string;
  engineVersion?: string;
  method?: "deterministic_hmac" | "provider_native" | "entropy+hmac" | "wasm-in-process";
  inputHash?: string;
  outputHash?: string;
}

export interface BundleSanitizer {
  sanitizeText(text: string, request: SanitizerRequest): Promise<SanitizerResult>;
}

export interface ImportBundleBuildOptions {
  sanitizer?: BundleSanitizer;
  saltFingerprint?: string;
}

export interface SanitizationSummary {
  engine_name: string;
  engine_version: string;
  method: "deterministic_hmac" | "provider_native" | "entropy+hmac" | "wasm-in-process";
  token_format: "[HIDDEN:<id>]";
  salt_fingerprint: string;
  redaction_count: number;
  redactions_by_type: Record<string, number>;
  status: "sanitized" | "none" | "partial" | "error";
  input_hash?: string;
  output_hash?: string;
  applied_to?: Array<
    | "ai_prompt"
    | "pr_comment"
    | "evidence_bundle"
    | "sarif"
    | "council_prompt"
    | "webhook_payload"
    | "docsync_pack"
  >;
}

import { createHash, randomUUID } from "node:crypto";
import type {
  BundleSanitizer,
  EmittedBundle,
  GuardSpineImportOptions,
  GuardSpineImportResponse,
  ImportBundleBuildOptions,
  ImportBundle,
  ImportBundleItem,
  SanitizationSummary,
} from "./types.js";

function ensureKernel(): Promise<typeof import("@guardspine/kernel")> {
  return import("@guardspine/kernel");
}

function normalizeItemId(index: number, kind: string): string {
  return `item-${index}-${kind}`;
}

function contentTypeForKind(kind: string): string {
  return `guardspine/webhook/${kind}`;
}

export async function buildImportBundle(
  bundle: EmittedBundle,
  options: ImportBundleBuildOptions = {}
): Promise<ImportBundle> {
  let kernel: typeof import("@guardspine/kernel");
  try {
    kernel = await ensureKernel();
  } catch {
    throw new Error("@guardspine/kernel is required to build import bundles");
  }

  if (typeof kernel.sealBundle !== "function") {
    throw new Error("@guardspine/kernel is missing sealBundle()");
  }

  let items: ImportBundleItem[] = bundle.items.map((item, idx) => ({
    item_id: normalizeItemId(idx, item.kind),
    content_type: contentTypeForKind(item.kind),
    content: item.content,
  }));

  let sanitization: SanitizationSummary | undefined;
  if (options.sanitizer) {
    const sanitized = await sanitizeImportItems(items, options.sanitizer, options.saltFingerprint);
    items = sanitized.items;
    sanitization = sanitized.summary;
  }

  items = items.map((item, idx) => ({
    ...item,
    content: {
      kind: bundle.items[idx].kind,
      summary: bundle.items[idx].summary,
      url: bundle.items[idx].url,
      content: item.content,
    },
  }));

  let version: ImportBundle["version"] = sanitization ? "0.2.1" : "0.2.0";

  const draft: ImportBundle = {
    bundle_id: bundle.bundle_id || randomUUID(),
    version,
    created_at: bundle.created_at || new Date().toISOString(),
    items,
    sanitization,
    metadata: {
      artifact_id: bundle.artifactId,
      risk_tier: bundle.riskTier,
      scope: bundle.scope,
      provider: bundle.provider,
    },
  };

  let sealed: {
    items: ImportBundleItem[];
    immutabilityProof: ImportBundle["immutability_proof"];
  };
  try {
    sealed = kernel.sealBundle(draft) as unknown as {
      items: ImportBundleItem[];
      immutabilityProof: ImportBundle["immutability_proof"];
    };
  } catch (err) {
    // Compatibility fallback for older kernels that may reject 0.2.1 version strings.
    if (version === "0.2.1") {
      const message = err instanceof Error ? err.message : String(err);
      if (/(version|0\.2\.0|0\.2\.1)/i.test(message)) {
        version = "0.2.0";
        draft.version = "0.2.0";
        sealed = kernel.sealBundle(draft) as unknown as {
          items: ImportBundleItem[];
          immutabilityProof: ImportBundle["immutability_proof"];
        };
      } else {
        throw err;
      }
    } else {
      throw err;
    }
  }

  if (!sealed.immutabilityProof) {
    throw new Error("Kernel sealing did not return immutability_proof");
  }

  return {
    ...draft,
    version,
    items: sealed.items,
    immutability_proof: sealed.immutabilityProof,
  };
}

export async function postImportBundle(
  bundle: ImportBundle,
  options: GuardSpineImportOptions
): Promise<GuardSpineImportResponse> {
  const url = new URL("/api/v1/bundles/import", options.baseUrl);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers ?? {}),
  };
  if (options.token) {
    headers.Authorization = `Bearer ${options.token}`;
  }

  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 10000;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(bundle),
      signal: controller.signal,
    });
    const text = await response.text();
    const data = text ? safeJsonParse(text) : undefined;
    return {
      ok: response.ok,
      status: response.status,
      data,
      error: response.ok ? undefined : text,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function sha256(input: string): string {
  return "sha256:" + createHash("sha256").update(input, "utf8").digest("hex");
}

function mergeCounts(
  base: Record<string, number>,
  extra: Record<string, number>
): Record<string, number> {
  const merged: Record<string, number> = { ...base };
  for (const [key, value] of Object.entries(extra || {})) {
    const numeric = Number.isFinite(value) ? value : 0;
    merged[key] = (merged[key] ?? 0) + numeric;
  }
  return merged;
}

async function sanitizeImportItems(
  items: ImportBundleItem[],
  sanitizer: BundleSanitizer,
  saltFingerprint = "sha256:00000000"
): Promise<{ items: ImportBundleItem[]; summary: SanitizationSummary }> {
  const summary: SanitizationSummary = {
    engine_name: "pii-shield",
    engine_version: "unknown",
    method: "provider_native",
    token_format: "[HIDDEN:<id>]",
    salt_fingerprint: saltFingerprint,
    redaction_count: 0,
    redactions_by_type: {},
    status: "none",
    applied_to: ["webhook_payload"],
  };

  const sanitizedItems: ImportBundleItem[] = [];
  const allRaw: string[] = [];
  const allOutput: string[] = [];
  for (const item of items) {
    const raw = JSON.stringify(item.content);
    const result = await sanitizer.sanitizeText(raw, {
      inputFormat: "json",
      purpose: "webhook_payload",
      includeFindings: true,
    });

    summary.engine_name = result.engineName ?? summary.engine_name;
    summary.engine_version = result.engineVersion ?? summary.engine_version;
    summary.method = result.method ?? summary.method;
    summary.redaction_count += result.redactionCount;
    summary.redactions_by_type = mergeCounts(summary.redactions_by_type, result.redactionsByType);
    allRaw.push(raw);
    allOutput.push(result.sanitizedText);
    if (result.changed) {
      summary.status = "sanitized";
    }

    let content = item.content;
    if (result.changed) {
      try {
        content = JSON.parse(result.sanitizedText);
      } catch {
        summary.status = summary.status === "sanitized" ? "partial" : "error";
      }
    }

    sanitizedItems.push({ ...item, content });
  }

  summary.input_hash = sha256(allRaw.join(""));
  summary.output_hash = sha256(allOutput.join(""));

  return { items: sanitizedItems, summary };
}

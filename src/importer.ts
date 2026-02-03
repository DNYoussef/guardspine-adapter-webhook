import { randomUUID } from "node:crypto";
import type {
  EmittedBundle,
  GuardSpineImportOptions,
  GuardSpineImportResponse,
  ImportBundle,
  ImportBundleItem,
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

export async function buildImportBundle(bundle: EmittedBundle): Promise<ImportBundle> {
  let kernel: typeof import("@guardspine/kernel");
  try {
    kernel = await ensureKernel();
  } catch {
    throw new Error("@guardspine/kernel is required to build import bundles");
  }

  if (typeof kernel.sealBundle !== "function") {
    throw new Error("@guardspine/kernel is missing sealBundle()");
  }

  const items: ImportBundleItem[] = bundle.items.map((item, idx) => ({
    item_id: normalizeItemId(idx, item.kind),
    content_type: contentTypeForKind(item.kind),
    content: {
      kind: item.kind,
      summary: item.summary,
      url: item.url,
      content: item.content,
    },
  }));

  const draft: ImportBundle = {
    bundle_id: bundle.bundle_id || randomUUID(),
    version: "0.2.0",
    created_at: bundle.created_at || new Date().toISOString(),
    items,
    metadata: {
      artifact_id: bundle.artifactId,
      risk_tier: bundle.riskTier,
      scope: bundle.scope,
      provider: bundle.provider,
    },
  };

  const sealed = kernel.sealBundle(draft) as unknown as {
    items: ImportBundleItem[];
    immutabilityProof: ImportBundle["immutability_proof"];
  };

  if (!sealed.immutabilityProof) {
    throw new Error("Kernel sealing did not return immutability_proof");
  }

  return {
    ...draft,
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

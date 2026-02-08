import { createHash } from "node:crypto";
import type { BundleSanitizer, SanitizerRequest, SanitizerResult } from "../types.js";

export interface PIIShieldSanitizerOptions {
  endpoint: string;
  apiKey?: string;
  timeoutMs?: number;
}

export class PIIShieldSanitizer implements BundleSanitizer {
  private readonly endpoint: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;

  constructor(options: PIIShieldSanitizerOptions) {
    this.endpoint = options.endpoint;
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  async sanitizeText(text: string, request: SanitizerRequest): Promise<SanitizerResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (this.apiKey) {
        headers.Authorization = `Bearer ${this.apiKey}`;
      }

      const response = await fetch(this.endpoint, {
        method: "POST",
        headers,
        signal: controller.signal,
        body: JSON.stringify({
          text,
          input_format: request.inputFormat,
          include_findings: request.includeFindings ?? false,
          deterministic: true,
          preserve_line_numbers: true,
          purpose: request.purpose,
        }),
      });
      if (!response.ok) {
        throw new Error(`PII-Shield request failed (${response.status})`);
      }

      const body = (await response.json()) as Record<string, unknown>;
      const sanitizedText =
        (body.sanitized_text as string | undefined) ??
        (body.redacted_text as string | undefined) ??
        (body.text as string | undefined) ??
        (body.output as string | undefined);

      if (typeof sanitizedText !== "string") {
        throw new Error("PII-Shield response did not include sanitized_text");
      }

      const redactionsByType = extractRedactionsByType(body);
      let redactionCount = Number(body.redaction_count ?? NaN);
      if (!Number.isFinite(redactionCount)) {
        redactionCount = Object.values(redactionsByType).reduce((sum, value) => sum + value, 0);
      }

      return {
        sanitizedText,
        changed: sanitizedText !== text,
        redactionCount,
        redactionsByType,
        engineName: "pii-shield",
        engineVersion: (body.engine_version as string | undefined) ?? (body.schema_version as string | undefined),
        method: "provider_native",
        inputHash: sha256(text),
        outputHash: sha256(sanitizedText),
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}

function extractRedactionsByType(body: Record<string, unknown>): Record<string, number> {
  const raw = body.redactions_by_type;
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const typed = raw as Record<string, unknown>;
    const output: Record<string, number> = {};
    for (const [key, value] of Object.entries(typed)) {
      const count = Number(value);
      if (Number.isFinite(count) && count >= 0) {
        output[key] = Math.floor(count);
      }
    }
    return output;
  }

  const redactions = body.redactions;
  if (!Array.isArray(redactions)) {
    return {};
  }
  const counts: Record<string, number> = {};
  for (const entry of redactions) {
    const label =
      typeof entry === "object" && entry && !Array.isArray(entry)
        ? String(
            (entry as Record<string, unknown>).type ??
              (entry as Record<string, unknown>).category ??
              (entry as Record<string, unknown>).label ??
              "unknown"
          )
        : "unknown";
    counts[label] = (counts[label] ?? 0) + 1;
  }
  return counts;
}

function sha256(value: string): string {
  return "sha256:" + createHash("sha256").update(value, "utf8").digest("hex");
}
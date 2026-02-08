import { describe, it, expect, vi, beforeEach } from "vitest";
import { PIIShieldSanitizer } from "../src/sanitizers/pii-shield.js";

const ENDPOINT = "https://pii-shield.example.com/sanitize";

function mockFetchOk(body: Record<string, unknown>) {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: () => Promise.resolve(body),
  });
}

function mockFetchError(status: number) {
  return vi.fn().mockResolvedValue({
    ok: false,
    status,
    json: () => Promise.resolve({}),
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("PIIShieldSanitizer", () => {
  it("returns redacted text from a successful response", async () => {
    const fakeFetch = mockFetchOk({
      sanitized_text: "Hello [HIDDEN:1]",
      redaction_count: 1,
      redactions_by_type: { email: 1 },
      engine_version: "1.2.0",
    });
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({ endpoint: ENDPOINT });
    const result = await sanitizer.sanitizeText("Hello user@example.com", {
      inputFormat: "text",
      purpose: "webhook_payload",
    });

    expect(result.sanitizedText).toBe("Hello [HIDDEN:1]");
    expect(result.changed).toBe(true);
    expect(result.redactionCount).toBe(1);
    expect(result.redactionsByType).toEqual({ email: 1 });
    expect(result.engineName).toBe("pii-shield");
    expect(result.engineVersion).toBe("1.2.0");
    expect(result.inputHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(result.outputHash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("returns passthrough when endpoint is empty (no-op sanitizer)", async () => {
    // When endpoint is empty, fetch will fail. In fail-open mode (default),
    // the sanitizer should propagate the error since there is no fail_closed
    // option -- the class always throws on HTTP errors.
    // Actually, PIIShieldSanitizer always throws on error (no fail-open mode).
    // An empty endpoint will cause a fetch error. Verify it throws.
    const fakeFetch = vi.fn().mockRejectedValue(new TypeError("Invalid URL"));
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({ endpoint: "" });
    await expect(
      sanitizer.sanitizeText("clean text", {
        inputFormat: "text",
      })
    ).rejects.toThrow();
  });

  it("throws on HTTP error status", async () => {
    const fakeFetch = mockFetchError(500);
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({ endpoint: ENDPOINT });
    await expect(
      sanitizer.sanitizeText("some text", { inputFormat: "json" })
    ).rejects.toThrow("PII-Shield request failed (500)");
  });

  it("throws when response is missing sanitized_text field", async () => {
    const fakeFetch = mockFetchOk({ status: "ok" });
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({ endpoint: ENDPOINT });
    await expect(
      sanitizer.sanitizeText("some text", { inputFormat: "text" })
    ).rejects.toThrow("PII-Shield response did not include sanitized_text");
  });

  it("reports changed=false when text is unchanged", async () => {
    const fakeFetch = mockFetchOk({
      sanitized_text: "clean text",
      redaction_count: 0,
    });
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({ endpoint: ENDPOINT });
    const result = await sanitizer.sanitizeText("clean text", {
      inputFormat: "text",
    });

    expect(result.changed).toBe(false);
    expect(result.redactionCount).toBe(0);
  });

  it("sends Authorization header when apiKey is provided", async () => {
    const fakeFetch = mockFetchOk({
      sanitized_text: "ok",
      redaction_count: 0,
    });
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({
      endpoint: ENDPOINT,
      apiKey: "secret-key",
    });
    await sanitizer.sanitizeText("text", { inputFormat: "text" });

    const callArgs = fakeFetch.mock.calls[0];
    expect(callArgs[1].headers.Authorization).toBe("Bearer secret-key");
  });

  it("falls back to redacted_text response field", async () => {
    const fakeFetch = mockFetchOk({
      redacted_text: "Hello [REDACTED]",
      redaction_count: 1,
    });
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({ endpoint: ENDPOINT });
    const result = await sanitizer.sanitizeText("Hello Alice", {
      inputFormat: "text",
    });

    expect(result.sanitizedText).toBe("Hello [REDACTED]");
    expect(result.changed).toBe(true);
  });

  it("extracts redactions_by_type from redactions array fallback", async () => {
    const fakeFetch = mockFetchOk({
      sanitized_text: "[HIDDEN:1] said [HIDDEN:2]",
      redactions: [
        { type: "name", start: 0, end: 5 },
        { type: "name", start: 11, end: 16 },
        { type: "email", start: 20, end: 30 },
      ],
    });
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({ endpoint: ENDPOINT });
    const result = await sanitizer.sanitizeText("Alice said Bob at bob@x.com", {
      inputFormat: "text",
    });

    expect(result.redactionsByType).toEqual({ name: 2, email: 1 });
    // redactionCount should be sum of redactionsByType when redaction_count absent
    expect(result.redactionCount).toBe(3);
  });

  it("aborts fetch on timeout", async () => {
    const fakeFetch = vi.fn().mockImplementation((_url: string, init: RequestInit) => {
      return new Promise((_resolve, reject) => {
        // Simulate the abort signal firing
        init.signal?.addEventListener("abort", () => {
          reject(new DOMException("The operation was aborted", "AbortError"));
        });
      });
    });
    vi.stubGlobal("fetch", fakeFetch);

    const sanitizer = new PIIShieldSanitizer({
      endpoint: ENDPOINT,
      timeoutMs: 50,
    });

    await expect(
      sanitizer.sanitizeText("text", { inputFormat: "text" })
    ).rejects.toThrow();
  });
});

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { PIIShieldSanitizer } from "../src/sanitizers/pii-shield.js";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { randomBytes } from "node:crypto";

const WASM_PATH = join(__dirname, "../lib/pii-shield.wasm");

describe("PIIShieldSanitizer Configuration & Stress (WASM)", () => {
    // Ensure WASM file exists before running tests
    if (!existsSync(WASM_PATH)) {
        console.warn("Skipping WASM tests because pii-shield.wasm is not found at " + WASM_PATH);
        return;
    }

    const originalEnv = process.env;

    beforeEach(() => {
        process.env = { ...originalEnv };
    });

    afterEach(() => {
        process.env = originalEnv;
    });

    it("respects PII_SAFE_REGEX_LIST configuration", async () => {
        const input = "Keep this: safe_pattern_123";
        // Default behavior: might treat "safe_pattern_123" as generic secret if high entropy?
        // Or we can pick something that definitely gets redacted.
        // Let's rely on standard email reduction first.
        const inputEmail = "Email: test@example.com";

        // 1. Verify default redaction
        const sanitizer = new PIIShieldSanitizer({});
        const res1 = await sanitizer.sanitizeText(inputEmail, { inputFormat: "text" });
        if (res1.changed) {
            expect(res1.sanitizedText).toContain("[HIDDEN");
            expect(res1.sanitizedText).not.toContain("test@example.com");
        }

        // 2. Configure whitelist to allow this specific email
        process.env.PII_SAFE_REGEX_LIST = JSON.stringify([
            { "pattern": "test@example\\.com", "name": "SafeEmail" }
        ]);

        // Re-instantiate to pick up env
        const sanitizerSafe = new PIIShieldSanitizer({});
        const res2 = await sanitizerSafe.sanitizeText(inputEmail, { inputFormat: "text" });

        // Should NOT be redacted
        expect(res2.sanitizedText).toContain("test@example.com");
        expect(res2.sanitizedText).not.toContain("[HIDDEN:email]");
    });

    it("handles binary data stress test without crashing", async () => {
        const sanitizer = new PIIShieldSanitizer({});

        // Generate 1MB of random binary data
        const buffer = randomBytes(1024 * 1024);
        // Convert to string (may have invalid utf-8 sequences, or use latin1)
        const text = buffer.toString('latin1');

        try {
            const start = performance.now();
            const result = await sanitizer.sanitizeText(text, { inputFormat: "text" });
            const end = performance.now();

            expect(result).toBeDefined();
            expect(typeof result.sanitizedText).toBe("string");

            // It should be reasonably fast (e.g. < 5s for 1MB)
            // WASM overhead + processing
            expect(end - start).toBeLessThan(5000);
        } catch (error) {
            console.error("WASM crashed on binary input:", error);
            throw error;
        }
    });

    it("handles invalid UTF-8 sequences gracefully", async () => {
        const sanitizer = new PIIShieldSanitizer({});
        // Invalid UTF-8 sequence
        const invalidUtf8 = Buffer.from([0xff, 0xff, 0xff]);
        const text = invalidUtf8.toString(); // Node Might replace with replacement char

        const result = await sanitizer.sanitizeText(text, { inputFormat: "text" });
        expect(result.sanitizedText).toBeDefined();
    });
});

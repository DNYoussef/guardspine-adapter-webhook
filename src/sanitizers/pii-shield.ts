import { readFile } from "node:fs/promises";
import { openSync, readFileSync, writeFileSync, unlinkSync, closeSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

// @ts-ignore - node:wasi is available in node 20+ (might require flag in older versions)
import { WASI } from "node:wasi";

import type { BundleSanitizer, SanitizerRequest, SanitizerResult } from "../types.js";

function sha256(text: string): string {
  return "sha256:" + createHash("sha256").update(text).digest("hex");
}

export interface PIIShieldConfig {
  /**
   * Ignored in WASM mode (local execution)
   */
  endpoint?: string;
  /**
   * Ignored in WASM mode
   */
  apiKey?: string;
  /**
   * Timeout in milliseconds for execution
   */
  timeoutMs?: number;
}

export class PIIShieldSanitizer implements BundleSanitizer {
  private wasmPath: string;

  constructor(private config: PIIShieldConfig) {
    const __dirname = fileURLToPath(new URL(".", import.meta.url));
    this.wasmPath = join(__dirname, "../../lib/pii-shield.wasm");
  }

  async sanitizeText(text: string, request: SanitizerRequest): Promise<SanitizerResult> {
    const id = randomUUID();
    const inFile = join(tmpdir(), `pii_in_${id}`);
    const outFile = join(tmpdir(), `pii_out_${id}`);
    const errFile = join(tmpdir(), `pii_err_${id}`);

    try {
      // Write input to temp file (Stdin)
      // Ensure newline for line-based scanner in Go
      const content = text.endsWith("\n") ? text : text + "\n";
      writeFileSync(inFile, content);

      // Open File Descriptors
      // 0: stdin, 1: stdout, 2: stderr
      const stdinFd = openSync(inFile, "r");
      const stdoutFd = openSync(outFile, "w");
      const stderrFd = openSync(errFile, "w");

      // Initialize WASI
      // Note: process.env inheritance satisfies user requirement
      const wasi = new WASI({
        args: ["pii-shield"],
        env: process.env,
        stdin: stdinFd,
        stdout: stdoutFd,
        stderr: stderrFd,
        version: "preview1",
      });

      // Load and Instantiate WASM
      const wasmBuffer = await readFile(this.wasmPath);
      const wasmModule = await WebAssembly.compile(wasmBuffer);
      const instance = await WebAssembly.instantiate(wasmModule, wasi.getImportObject());

      // Run
      // WASI start blocks until main exits (which happens when stdin EOF is reached)
      try {
        wasi.start(instance);
      } catch (err: any) {
        // Ignore exit code 0
        if (err.code !== 0 && err.code !== "EFAULT") {
          console.warn("WASI execution exited with", err);
        }
      }

      // Explicitly close FDs to flush
      closeSync(stdinFd);
      closeSync(stdoutFd);
      closeSync(stderrFd);

      // Read Output
      let resultText = "";
      try {
        resultText = readFileSync(outFile, "utf-8");
      } catch (readErr) {
        console.error("Failed to read WASM output", readErr);
        // Try to read stderr for debugging
        try {
          const errText = readFileSync(errFile, "utf-8");
          if (errText) console.error("WASM Stderr:", errText);
        } catch (e) { }
      }

      const sanitizedText = resultText.trim();
      const changes = (sanitizedText !== text.trim());
      const redactionCount = changes ? (sanitizedText.match(/\[HIDDEN/g) || []).length : 0;

      return {
        sanitizedText,
        changed: changes,
        redactionCount,
        redactionsByType: {},
        engineName: "pii-shield-wasm",
        engineVersion: "1.0.0",
        method: "wasm-in-process",
        inputHash: sha256(text),
        outputHash: sha256(sanitizedText),
      };

    } catch (err) {
      console.error("WASM Sanitization failed:", err);
      throw err;
    } finally {
      // Cleanup temp files
      try {
        if (inFile) unlinkSync(inFile);
        if (outFile) unlinkSync(outFile);
        if (errFile) unlinkSync(errFile);
      } catch (ignored) { }
    }
  }
}
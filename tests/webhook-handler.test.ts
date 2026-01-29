import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import {
  WebhookHandler,
  NoMatchingProviderError,
  SignatureValidationError,
} from "../src/webhook-handler.js";
import { GitHubProvider } from "../src/providers/github.js";
import { GitLabProvider } from "../src/providers/gitlab.js";
import { GenericProvider } from "../src/providers/generic.js";

const TEST_SECRET = "test-secret-123";

function githubSignature(body: string, secret: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body, "utf8").digest("hex");
}

const sampleGitHubPR = JSON.stringify({
  action: "opened",
  pull_request: {
    number: 42,
    head: { sha: "abc123def456" },
    diff_url: "https://github.com/org/repo/pull/42.diff",
    user: { login: "testuser" },
    labels: [{ name: "bug" }, { name: "security" }],
  },
  repository: { full_name: "org/repo" },
});

const sampleGitHubPush = JSON.stringify({
  ref: "refs/heads/main",
  after: "deadbeef12345678",
  compare: "https://github.com/org/repo/compare/aaa...bbb",
  pusher: { name: "pusheruser" },
  repository: { full_name: "org/repo" },
  commits: [
    { added: ["new.ts"], removed: [], modified: ["src/index.ts"] },
  ],
});

describe("WebhookHandler", () => {
  it("throws if no providers given", () => {
    expect(() => new WebhookHandler([])).toThrow("At least one");
  });

  it("throws NoMatchingProviderError when no provider matches", async () => {
    const handler = new WebhookHandler([new GitHubProvider()]);
    await expect(
      handler.handleRequest({ "x-custom": "val" }, "{}")
    ).rejects.toThrow(NoMatchingProviderError);
  });

  it("parses a GitHub pull_request event", async () => {
    const handler = new WebhookHandler([new GitHubProvider()]);
    const event = await handler.handleRequest(
      { "x-github-event": "pull_request" },
      sampleGitHubPR
    );
    expect(event.provider).toBe("github");
    expect(event.eventType).toBe("pull_request");
    expect(event.repo).toBe("org/repo");
    expect(event.prNumber).toBe(42);
    expect(event.author).toBe("testuser");
    expect(event.labels).toEqual(["bug", "security"]);
    expect(event.action).toBe("opened");
  });

  it("parses a GitHub push event with changed files", async () => {
    const handler = new WebhookHandler([new GitHubProvider()]);
    const event = await handler.handleRequest(
      { "x-github-event": "push" },
      sampleGitHubPush
    );
    expect(event.eventType).toBe("push");
    expect(event.sha).toBe("deadbeef12345678");
    expect(event.changedFiles).toContain("new.ts");
    expect(event.changedFiles).toContain("src/index.ts");
  });

  it("validates GitHub HMAC signature", async () => {
    const handler = new WebhookHandler([
      new GitHubProvider({ secret: TEST_SECRET }),
    ]);
    const sig = githubSignature(sampleGitHubPR, TEST_SECRET);
    const event = await handler.handleRequest(
      { "x-github-event": "pull_request", "x-hub-signature-256": sig },
      sampleGitHubPR
    );
    expect(event.provider).toBe("github");
  });

  it("rejects invalid GitHub signature", async () => {
    const handler = new WebhookHandler([
      new GitHubProvider({ secret: TEST_SECRET }),
    ]);
    await expect(
      handler.handleRequest(
        { "x-github-event": "push", "x-hub-signature-256": "sha256=bad" },
        sampleGitHubPush
      )
    ).rejects.toThrow(SignatureValidationError);
  });

  it("rejects missing GitHub signature when secret is set", async () => {
    const handler = new WebhookHandler([
      new GitHubProvider({ secret: TEST_SECRET }),
    ]);
    await expect(
      handler.handleRequest({ "x-github-event": "push" }, sampleGitHubPush)
    ).rejects.toThrow(SignatureValidationError);
  });

  it("normalizes header keys to lowercase", async () => {
    const handler = new WebhookHandler([new GitHubProvider()]);
    const event = await handler.handleRequest(
      { "X-GitHub-Event": "push" },
      sampleGitHubPush
    );
    expect(event.provider).toBe("github");
  });
});

describe("GitLabProvider", () => {
  const sampleMR = JSON.stringify({
    object_attributes: {
      iid: 7,
      action: "open",
      url: "https://gitlab.com/org/repo/-/merge_requests/7",
      last_commit: { id: "gitlab123abc" },
      labels: [{ title: "critical" }],
    },
    user: { username: "gluser" },
    project: { path_with_namespace: "org/repo" },
  });

  it("parses a GitLab merge_request event", async () => {
    const handler = new WebhookHandler([new GitLabProvider()]);
    const event = await handler.handleRequest(
      { "x-gitlab-event": "Merge Request Hook" },
      sampleMR
    );
    expect(event.provider).toBe("gitlab");
    expect(event.eventType).toBe("merge_request");
    expect(event.prNumber).toBe(7);
    expect(event.author).toBe("gluser");
    expect(event.labels).toEqual(["critical"]);
  });

  it("validates GitLab token", async () => {
    const handler = new WebhookHandler([
      new GitLabProvider({ secretToken: "gl-secret" }),
    ]);
    const event = await handler.handleRequest(
      { "x-gitlab-event": "Push Hook", "x-gitlab-token": "gl-secret" },
      JSON.stringify({ project: { path_with_namespace: "a/b" }, commits: [] })
    );
    expect(event.provider).toBe("gitlab");
  });

  it("rejects invalid GitLab token", async () => {
    const handler = new WebhookHandler([
      new GitLabProvider({ secretToken: "gl-secret" }),
    ]);
    await expect(
      handler.handleRequest(
        { "x-gitlab-event": "Push Hook", "x-gitlab-token": "wrong" },
        "{}"
      )
    ).rejects.toThrow(SignatureValidationError);
  });
});

describe("GenericProvider", () => {
  it("always matches and passes through fields", async () => {
    const handler = new WebhookHandler([new GenericProvider()]);
    const body = JSON.stringify({
      repo: "custom/repo",
      author: "someone",
      sha: "aaa111",
      labels: ["foo"],
      changed_files: ["bar.ts"],
    });
    const event = await handler.handleRequest({}, body);
    expect(event.provider).toBe("generic");
    expect(event.repo).toBe("custom/repo");
    expect(event.labels).toEqual(["foo"]);
    expect(event.changedFiles).toEqual(["bar.ts"]);
  });
});

describe("Provider priority", () => {
  it("picks GitHub over Generic when GitHub headers present", async () => {
    const handler = new WebhookHandler([
      new GitHubProvider(),
      new GenericProvider(),
    ]);
    const event = await handler.handleRequest(
      { "x-github-event": "push" },
      sampleGitHubPush
    );
    expect(event.provider).toBe("github");
  });

  it("falls back to Generic when no specific provider matches", async () => {
    const handler = new WebhookHandler([
      new GitHubProvider(),
      new GitLabProvider(),
      new GenericProvider(),
    ]);
    const event = await handler.handleRequest(
      {},
      JSON.stringify({ repo: "fallback/repo" })
    );
    expect(event.provider).toBe("generic");
  });
});

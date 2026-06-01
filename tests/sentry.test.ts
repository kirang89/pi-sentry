import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  containsSecretLikeText,
  isSensitiveBashCommand,
  isSensitivePath,
  redactText,
} from "../extensions/sentry.ts";

describe("redactText", () => {
  it("redacts JSON secret key-value pairs", () => {
    const input = '{ "token": "my-secret-token-value" }';
    assert.equal(redactText(input).text, '{ "token": "[REDACTED]" }');
  });

  it("redacts env-style snake_case secret names", () => {
    const input = "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    assert.equal(redactText(input).text, "AWS_SECRET_ACCESS_KEY=[REDACTED]");
  });

  it("redacts camelCase secret names", () => {
    const input = 'const dbPassword = "correct-horse-battery-staple";';
    assert.equal(redactText(input).text, 'const dbPassword = "[REDACTED]";');
  });

  it("redacts bearer tokens", () => {
    const token = "abcdefghijkl" + "mnopqrstuvwxyz123456";
    const input = `Authorization: Bearer ${token}`;
    assert.equal(redactText(input).text, "Authorization: Bearer [REDACTED]");
  });

  it("redacts database URL passwords", () => {
    const password = "correct-horse-" + "battery-staple";
    const input = `postgres://user:${password}@example.com/db`;
    assert.equal(redactText(input).text, "postgres://user:[REDACTED]@example.com/db");
  });

  it("redacts private key blocks", () => {
    const keyBody = "abcdefghijklmnopqrstuvwxyz" + "0123456789";
    const input = ["-----BEGIN PRIVATE KEY-----", keyBody, "-----END PRIVATE KEY-----"].join("\n");
    assert.equal(redactText(input).text, "[PRIVATE_KEY_REDACTED]");
  });

  it("redacts provider-specific keys", () => {
    const input = "sk-ant-" + "abcdefghijklmnopqrstuvwxyz1234567890";
    assert.equal(redactText(input).text, "[ANTHROPIC_KEY_REDACTED]");
  });
});

describe("isSensitivePath", () => {
  it("blocks common secret files", () => {
    assert.equal(isSensitivePath(".env"), true);
    assert.equal(isSensitivePath("/home/me/.aws/credentials"), true);
    assert.equal(isSensitivePath("/home/me/.kube/config"), true);
    assert.equal(isSensitivePath("terraform.tfvars"), true);
  });

  it("allows example and template files", () => {
    assert.equal(isSensitivePath(".env.example"), false);
    assert.equal(isSensitivePath("secrets.example.yaml"), false);
    assert.equal(isSensitivePath("config.template.json"), false);
  });
});

describe("isSensitiveBashCommand", () => {
  it("blocks bash reads of sensitive paths", () => {
    assert.equal(isSensitiveBashCommand("cat .env"), true);
    assert.equal(isSensitiveBashCommand("rg token ~/.aws/credentials"), true);
  });

  it("blocks known secret dump commands", () => {
    assert.equal(isSensitiveBashCommand("printenv"), true);
    assert.equal(isSensitiveBashCommand("gh auth token"), true);
    assert.equal(isSensitiveBashCommand("kubectl config view --raw"), true);
  });

  it("does not block ordinary searches", () => {
    assert.equal(isSensitiveBashCommand("rg token src"), false);
  });
});

describe("containsSecretLikeText", () => {
  it("detects embedded secret values", () => {
    const input = JSON.stringify({ apiKey: "abcdefghijkl" + "mnopqrstuvwx" });
    assert.equal(containsSecretLikeText(input), true);
  });
});

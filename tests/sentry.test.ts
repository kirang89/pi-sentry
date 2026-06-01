import { describe, it } from "node:test";
import assert from "node:assert/strict";
import sentryExtension, {
  containsSecretLikeText,
  isSensitiveBashCommand,
  isSensitivePath,
  redactText,
} from "../extensions/sentry.ts";

type Handler = (event: any, ctx: any) => any;

type Harness = {
  handlers: Record<string, Handler[]>;
  commands: Record<string, { handler: Handler }>;
  ctx: {
    hasUI: boolean;
    ui: { notifications: Array<{ message: string; level: string }>; notify(message: string, level: string): void };
  };
};

function createHarness(): Harness {
  const handlers: Harness["handlers"] = {};
  const commands: Harness["commands"] = {};
  const ctx: Harness["ctx"] = {
    hasUI: true,
    ui: {
      notifications: [],
      notify(message: string, level: string) {
        this.notifications.push({ message, level });
      },
    },
  };

  sentryExtension({
    on(eventName: string, handler: Handler) {
      handlers[eventName] ??= [];
      handlers[eventName].push(handler);
    },
    registerCommand(name: string, command: { handler: Handler }) {
      commands[name] = command;
    },
  } as any);

  return { handlers, commands, ctx };
}

async function emit(harness: Harness, eventName: string, event: any): Promise<any> {
  let result: any;
  for (const handler of harness.handlers[eventName] ?? []) {
    result = await handler(event, harness.ctx);
    if (result !== undefined) return result;
  }
  return result;
}

async function setSentryMode(harness: Harness, mode: "strict" | "redact-only"): Promise<void> {
  const command = harness.commands.sentry;
  assert.ok(command);
  await command.handler(mode, harness.ctx);
}

function toolCallEvent(toolName: string, input: Record<string, unknown>) {
  return { type: "tool_call", toolCallId: `${toolName}-1`, toolName, input };
}

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

describe("pi-sentry extension modes", () => {
  it("defaults to redact-only mode", async () => {
    const harness = createHarness();

    const result = await emit(harness, "tool_call", toolCallEvent("read", { path: ".env" }));

    assert.equal(result, undefined);
  });

  it("switches modes with the /sentry command", async () => {
    const harness = createHarness();

    const command = harness.commands.sentry;
    assert.ok(command);
    await command.handler("", harness.ctx);
    await setSentryMode(harness, "strict");

    assert.deepEqual(harness.ctx.ui.notifications.map((item) => item.message), [
      "pi-sentry mode: redact-only",
      "pi-sentry mode set to strict",
    ]);
  });
});

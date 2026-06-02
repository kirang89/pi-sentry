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

async function setSentryMode(harness: Harness, mode: "strict" | "redact-only" | "off"): Promise<void> {
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
    await setSentryMode(harness, "off");

    assert.deepEqual(harness.ctx.ui.notifications.map((item) => item.message), [
      "pi-sentry mode: redact-only",
      "pi-sentry mode set to strict",
      "pi-sentry mode set to off",
    ]);
  });

  it("shows all modes in the usage message", async () => {
    const harness = createHarness();

    const command = harness.commands.sentry;
    assert.ok(command);
    await command.handler("disabled", harness.ctx);

    assert.deepEqual(harness.ctx.ui.notifications.at(-1), {
      message: "Usage: /sentry strict | /sentry redact-only | /sentry off",
      level: "error",
    });
  });

  it("blocks sensitive read, grep, edit, and write tool calls in strict mode", async () => {
    const harness = createHarness();
    await setSentryMode(harness, "strict");

    assert.equal((await emit(harness, "tool_call", toolCallEvent("read", { path: ".env" }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("grep", { pattern: "token", path: ".env" }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("edit", { path: ".env", edits: [] }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("write", { path: ".env", content: "TOKEN=value" }))).block, true);
  });

  it("blocks sensitive user bash commands in strict mode", async () => {
    const harness = createHarness();
    await setSentryMode(harness, "strict");

    const result = await emit(harness, "user_bash", {
      type: "user_bash",
      command: "cat .env",
      excludeFromContext: false,
      cwd: process.cwd(),
    });

    assert.equal(result.result.exitCode, 1);
    assert.match(result.result.output, /Blocked user bash command/);
  });

  it("turns off blocking and redaction in off mode", async () => {
    const harness = createHarness();
    await setSentryMode(harness, "off");

    const readResult = await emit(harness, "tool_call", toolCallEvent("read", { path: ".env" }));
    assert.equal(readResult, undefined);

    const inputResult = await emit(harness, "input", {
      type: "input",
      text: "apiKey=" + "abcdefghijklmnopqrstuvwx",
      images: undefined,
      source: "interactive",
    });
    assert.deepEqual(inputResult, { action: "continue" });

    const toolResult = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "read-1",
      toolName: "read",
      input: { path: ".env" },
      content: [{ type: "text", text: "apiKey=" + "abcdefghijklmnopqrstuvwx" }],
      details: { token: "apiKey=" + "abcdefghijklmnopqrstuvwx" },
      isError: false,
    });
    assert.equal(toolResult, undefined);

    const userBashResult = await emit(harness, "user_bash", {
      type: "user_bash",
      command: "cat .env",
      excludeFromContext: false,
      cwd: process.cwd(),
    });
    assert.equal(userBashResult, undefined);

    const messageResult = await emit(harness, "message_end", {
      type: "message_end",
      message: {
        content: "apiKey=" + "abcdefghijklmnopqrstuvwx",
        details: { token: "apiKey=" + "abcdefghijklmnopqrstuvwx" },
      },
    });
    assert.equal(messageResult, undefined);
  });

  it("redacts sensitive user input", async () => {
    const harness = createHarness();
    const token = "abcdefghijkl" + "mnopqrstuvwxyz123456";

    const result = await emit(harness, "input", {
      type: "input",
      text: `Authorization: Bearer ${token}`,
      images: undefined,
      source: "interactive",
    });

    assert.deepEqual(result, {
      action: "transform",
      text: "Authorization: Bearer [REDACTED]",
      images: undefined,
    });
  });

  it("redacts sensitive read results in redact-only mode", async () => {
    const harness = createHarness();
    const apiKey = "abcdefghijkl" + "mnopqrstuvwx";

    const result = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "read-1",
      toolName: "read",
      input: { path: ".env" },
      content: [{ type: "text", text: `API_KEY=${apiKey}` }],
      details: undefined,
      isError: false,
    });

    assert.deepEqual(result.content, [{ type: "text", text: "[Contents of .env redacted for security]" }]);
  });

  it("redacts arbitrary details.data fields while preserving image data", async () => {
    const harness = createHarness();
    const secretData = "apiKey=" + "abcdefghijklmnopqrstuvwx";

    const result = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "custom-1",
      toolName: "custom",
      input: {},
      content: [],
      details: {
        data: secretData,
        image: { type: "image", data: secretData },
      },
      isError: false,
    });

    assert.equal(result.details.data, "apiKey=[REDACTED]");
    assert.equal(result.details.image.data, secretData);
  });

  it("redacts repeated object references without leaking the original object", async () => {
    const harness = createHarness();
    const secretData = "apiKey=" + "abcdefghijklmnopqrstuvwx";
    const shared = { token: secretData };

    const result = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "custom-1",
      toolName: "custom",
      input: {},
      content: [],
      details: {
        first: shared,
        second: shared,
      },
      isError: false,
    });

    assert.equal(result.details.first.token, "apiKey=[REDACTED]");
    assert.equal(result.details.second.token, "apiKey=[REDACTED]");
  });
});

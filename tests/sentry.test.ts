import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import sentryExtension, {
  containsSecretLikeText,
  isSensitiveBashCommand,
  isSensitivePath,
  loadSentryConfig,
  parseSentryConfig,
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
    const begin = "-----BEGIN " + "PRIVATE KEY-----";
    const end = "-----END " + "PRIVATE KEY-----";
    const input = [begin, keyBody, end].join("\n");
    assert.equal(redactText(input).text, "[PRIVATE_KEY_REDACTED]");
  });

  it("redacts escaped private key env values", () => {
    const keyBody = "abcdefghijklmnopqrstuvwxyz" + "0123456789";
    const begin = "-----BEGIN " + "PRIVATE KEY-----";
    const end = "-----END " + "PRIVATE KEY-----";
    const input = String.raw`PRIVATE_KEY=${begin}\n${keyBody}\n${end}`;
    assert.equal(redactText(input).text, "PRIVATE_KEY=[PRIVATE_KEY_REDACTED]");
  });

  it("redacts session cookie env values", () => {
    const input = "SESSION_COOKIE=s%3Arealworld.session.cookie.000000000000";
    assert.equal(redactText(input).text, "SESSION_COOKIE=[REDACTED]");
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
    assert.equal(isSensitivePath("/home/me/.ssh"), true);
    assert.equal(isSensitivePath("/home/me/.ssh/config"), true);
    assert.equal(isSensitivePath("/home/me/.ssh/known_hosts"), true);
    assert.equal(isSensitivePath("terraform.tfvars"), true);
  });

  it("allows example and template files", () => {
    assert.equal(isSensitivePath(".env.example"), false);
    assert.equal(isSensitivePath("secrets.example.yaml"), false);
    assert.equal(isSensitivePath("config.template.json"), false);
  });

  it("lets user allow paths override built-in blocks", () => {
    assert.equal(isSensitivePath(".env", { allowPaths: [".env"], blockPaths: [] }), false);
  });

  it("lets user block paths override built-in allows", () => {
    assert.equal(isSensitivePath(".env.example", { allowPaths: [], blockPaths: [".env.example"] }), true);
  });

  it("blocks when user allow and block rules conflict", () => {
    const config = { allowPaths: [".env"], blockPaths: [".env"] };
    assert.equal(isSensitivePath(".env", config), true);
  });

  it("matches configured glob paths", () => {
    const config = { allowPaths: [], blockPaths: ["private/**", "*.secret.json", "**/private.txt"] };
    assert.equal(isSensitivePath("private/token.txt", config), true);
    assert.equal(isSensitivePath("config/api.secret.json", config), true);
    assert.equal(isSensitivePath("private.txt", config), true);
  });
});

describe("pi-sentry config", () => {
  it("parses allow and block paths", () => {
    assert.deepEqual(parseSentryConfig({ allowPaths: [".env"], blockPaths: ["private/**"] }), {
      allowPaths: [".env"],
      blockPaths: ["private/**"],
    });
  });

  it("rejects invalid path lists", () => {
    assert.throws(() => parseSentryConfig({ allowPaths: ".env" }), /allowPaths must be an array/);
    assert.throws(() => parseSentryConfig({ blockPaths: [""] }), /blockPaths\[0\]/);
  });

  it("loads config from a pi-sentry.json file", async () => {
    const configDir = await mkdtemp(join(tmpdir(), "pi-sentry-"));
    await writeFile(join(configDir, "pi-sentry.json"), JSON.stringify({ allowPaths: [".env"], blockPaths: [] }));

    assert.deepEqual(await loadSentryConfig(configDir), { allowPaths: [".env"], blockPaths: [] });
  });

  it("uses empty config when pi-sentry.json is missing", async () => {
    const configDir = await mkdtemp(join(tmpdir(), "pi-sentry-"));

    assert.deepEqual(await loadSentryConfig(configDir), { allowPaths: [], blockPaths: [] });
  });
});

describe("isSensitiveBashCommand", () => {
  it("blocks bash reads of sensitive paths", () => {
    assert.equal(isSensitiveBashCommand("cat .env"), true);
    assert.equal(isSensitiveBashCommand("rg token ~/.aws/credentials"), true);
  });

  it("blocks sensitive commands after newlines and through shell wrappers", () => {
    assert.equal(isSensitiveBashCommand("printf ok\ncat .env"), true);
    assert.equal(isSensitiveBashCommand("bash -c 'cat .env'"), true);
    assert.equal(isSensitiveBashCommand("cp .env /tmp/exposed"), true);
    assert.equal(isSensitiveBashCommand("FILE=.env; cat \"$FILE\""), true);
    assert.equal(isSensitiveBashCommand("printf ok\nprintenv"), true);
  });

  it("blocks echoing secret-looking environment variables", () => {
    assert.equal(isSensitiveBashCommand("echo $OPENAI_API_KEY"), true);
    assert.equal(isSensitiveBashCommand('printf "%s\\n" "$GITHUB_TOKEN"'), true);
    assert.equal(isSensitiveBashCommand("echo ${AWS_SECRET_ACCESS_KEY}"), true);
  });

  it("blocks echoing secret-looking environment variables inside scripts", () => {
    assert.equal(isSensitiveBashCommand("bash -lc 'echo $OPENAI_API_KEY'"), true);
    assert.equal(isSensitiveBashCommand("cat > /tmp/debug.sh <<'EOF'\necho $DATABASE_PASSWORD\nEOF"), true);
  });

  it("does not block ordinary echo commands", () => {
    assert.equal(isSensitiveBashCommand("echo $PATH"), false);
    assert.equal(isSensitiveBashCommand("echo token"), false);
  });

  it("does not block ordinary searches", () => {
    assert.equal(isSensitiveBashCommand("rg token src"), false);
  });

  it("uses configured path allow rules for bash reads", () => {
    assert.equal(isSensitiveBashCommand("cat .env", { allowPaths: [".env"], blockPaths: [] }), false);
  });

  it("uses configured path block rules for bash reads", () => {
    assert.equal(isSensitiveBashCommand("cat .env.example", { allowPaths: [], blockPaths: [".env.example"] }), true);
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

    const toolCallResult = await emit(harness, "tool_call", toolCallEvent("read", { path: ".env" }));
    assert.equal(toolCallResult, undefined);

    const toolResult = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "read-1",
      toolName: "read",
      input: { path: ".env" },
      content: [{ type: "text", text: "API_KEY=" + "abcdefghijklmnopqrstuvwx" }],
      details: undefined,
      isError: false,
    });
    assert.deepEqual(toolResult.content, [{ type: "text", text: "[Contents of .env redacted for security]" }]);
  });

  it("switches modes with the /sentry command", async () => {
    const harness = createHarness();

    const command = harness.commands.sentry;
    assert.ok(command);
    await command.handler("", harness.ctx);
    await setSentryMode(harness, "strict");
    await setSentryMode(harness, "off");

    assert.match(harness.ctx.ui.notifications[0]?.message ?? "", /^pi-sentry mode: redact-only\n✗ .+pi-sentry\.json not loaded$/);
    assert.deepEqual(harness.ctx.ui.notifications.slice(1).map((item) => item.message), [
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
    assert.equal((await emit(harness, "tool_call", toolCallEvent("grep", { pattern: "token", glob: "*.env" }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("grep", { pattern: "token", glob: "**/.env" }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("grep", { pattern: "token", glob: "*.netrc" }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("edit", { path: ".env", edits: [] }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("write", { path: ".env", content: "TOKEN=value" }))).block, true);
  });

  it("allows safe tool calls in strict mode", async () => {
    const harness = createHarness();
    await setSentryMode(harness, "strict");

    assert.equal(await emit(harness, "tool_call", toolCallEvent("read", { path: "README.md" })), undefined);
    assert.equal(await emit(harness, "tool_call", toolCallEvent("grep", { pattern: "sentry", path: "README.md" })), undefined);
    assert.equal(await emit(harness, "tool_call", toolCallEvent("bash", { command: "echo hello" })), undefined);
    assert.equal(
      await emit(harness, "tool_call", toolCallEvent("write", { path: "notes.txt", content: "safe content" })),
      undefined,
    );
  });

  it("blocks reads through symlinks to sensitive files in strict mode", async () => {
    const directory = await mkdtemp(join(tmpdir(), "pi-sentry-"));
    const sensitivePath = join(directory, ".env");
    const aliasPath = join(directory, "settings.txt");
    await writeFile(sensitivePath, "API_KEY=secret");
    await symlink(sensitivePath, aliasPath);

    const harness = createHarness();
    await setSentryMode(harness, "strict");

    assert.equal((await emit(harness, "tool_call", toolCallEvent("read", { path: aliasPath }))).block, true);
  });

  it("blocks mutations through symlinked sensitive directories in strict mode", async () => {
    const directory = await mkdtemp(join(tmpdir(), "pi-sentry-"));
    const sensitiveDirectory = join(directory, ".ssh");
    const aliasDirectory = join(directory, "settings");
    await mkdir(sensitiveDirectory);
    await symlink(sensitiveDirectory, aliasDirectory);

    const harness = createHarness();
    await setSentryMode(harness, "strict");

    assert.equal(
      (await emit(harness, "tool_call", toolCallEvent("write", { path: join(aliasDirectory, "config.new"), content: "safe" }))).block,
      true,
    );
  });

  it("redacts reads through symlinks to sensitive files in redact-only mode", async () => {
    const directory = await mkdtemp(join(tmpdir(), "pi-sentry-"));
    const sensitivePath = join(directory, ".env");
    const aliasPath = join(directory, "settings.txt");
    await writeFile(sensitivePath, "API_KEY=opaque-value");
    await symlink(sensitivePath, aliasPath);

    const harness = createHarness();
    const result = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "read-1",
      toolName: "read",
      input: { path: aliasPath },
      content: [{ type: "text", text: "API_KEY=opaque-value" }],
      details: undefined,
      isError: false,
    });

    assert.deepEqual(result.content, [{ type: "text", text: `[Contents of ${aliasPath} redacted for security]` }]);
  });

  it("blocks .ssh directory access in strict mode", async () => {
    const harness = createHarness();
    await setSentryMode(harness, "strict");

    assert.equal((await emit(harness, "tool_call", toolCallEvent("read", { path: "~/.ssh/config" }))).block, true);
    assert.equal((await emit(harness, "tool_call", toolCallEvent("bash", { command: "cat ~/.ssh/known_hosts" }))).block, true);
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

  it("blocks echoing secret environment variables in strict mode", async () => {
    const harness = createHarness();
    await setSentryMode(harness, "strict");

    const toolResult = await emit(harness, "tool_call", toolCallEvent("bash", { command: "echo $OPENAI_API_KEY" }));
    assert.equal(toolResult.block, true);

    const userBashResult = await emit(harness, "user_bash", {
      type: "user_bash",
      command: "printf '%s\\n' \"$GITHUB_TOKEN\"",
      excludeFromContext: false,
      cwd: process.cwd(),
    });
    assert.equal(userBashResult.result.exitCode, 1);
  });

  it("shows mode and loaded config path in /sentry status", async () => {
    const configDir = await mkdtemp(join(tmpdir(), "pi-sentry-"));
    const configPath = join(configDir, "pi-sentry.json");
    await writeFile(configPath, JSON.stringify({ allowPaths: [], blockPaths: [] }));

    const originalConfigDir = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = configDir;
    try {
      const harness = createHarness();
      await emit(harness, "session_start", { type: "session_start", reason: "startup" });
      const command = harness.commands.sentry;
      assert.ok(command);
      await command.handler("", harness.ctx);

      assert.deepEqual(harness.ctx.ui.notifications.at(-1), {
        message: `pi-sentry mode: redact-only\n✓ ${configPath} loaded`,
        level: "info",
      });
    } finally {
      if (originalConfigDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = originalConfigDir;
    }
  });

  it("shows a failed config load in /sentry status", async () => {
    const configDir = await mkdtemp(join(tmpdir(), "pi-sentry-"));
    const configPath = join(configDir, "pi-sentry.json");
    await writeFile(configPath, "not JSON");

    const originalConfigDir = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = configDir;
    try {
      const harness = createHarness();
      await emit(harness, "session_start", { type: "session_start", reason: "startup" });
      const command = harness.commands.sentry;
      assert.ok(command);
      await command.handler("", harness.ctx);

      assert.deepEqual(harness.ctx.ui.notifications.at(-1), {
        message: `pi-sentry mode: redact-only\n✗ ${configPath} not loaded`,
        level: "info",
      });
    } finally {
      if (originalConfigDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = originalConfigDir;
    }
  });

  it("redacts secrets nested more than eight levels deep in tool details", async () => {
    const harness = createHarness();
    let details: Record<string, unknown> = { value: "apiKey=abcdefghijklmnopqrstuvwx" };
    for (let depth = 0; depth < 9; depth += 1) details = { nested: details };

    const result = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "custom-1",
      toolName: "custom",
      input: {},
      content: [],
      details,
      isError: false,
    });

    let redacted = result.details as Record<string, unknown>;
    for (let depth = 0; depth < 9; depth += 1) redacted = redacted.nested as Record<string, unknown>;
    assert.equal(redacted.value, "apiKey=[REDACTED]");
  });

  it("uses loaded config for strict mode path blocking", async () => {
    const configDir = await mkdtemp(join(tmpdir(), "pi-sentry-"));
    await writeFile(
      join(configDir, "pi-sentry.json"),
      JSON.stringify({ allowPaths: [".env"], blockPaths: [".env.example"] }),
    );

    const originalConfigDir = process.env.PI_CODING_AGENT_DIR;
    process.env.PI_CODING_AGENT_DIR = configDir;
    try {
      const harness = createHarness();
      await emit(harness, "session_start", { type: "session_start", reason: "startup" });
      await setSentryMode(harness, "strict");

      assert.equal(await emit(harness, "tool_call", toolCallEvent("read", { path: ".env" })), undefined);
      assert.equal((await emit(harness, "tool_call", toolCallEvent("read", { path: ".env.example" }))).block, true);
    } finally {
      if (originalConfigDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = originalConfigDir;
    }
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
    assert.deepEqual(harness.ctx.ui.notifications.at(-1), {
      message: "Sensitive data redacted from user input",
      level: "warning",
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
    assert.deepEqual(harness.ctx.ui.notifications.at(-1), {
      message: "Redacted contents of sensitive file: .env",
      level: "info",
    });
  });

  it("notifies the user when it redacts session history", async () => {
    const harness = createHarness();
    const result = await emit(harness, "message_end", {
      type: "message_end",
      message: { content: "apiKey=" + "abcdefghijklmnopqrstuvwx" },
    });

    assert.equal((result.message as { content: string }).content, "apiKey=[REDACTED]");
    assert.deepEqual(harness.ctx.ui.notifications.at(-1), {
      message: "Sensitive data redacted from session message",
      level: "info",
    });
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
    assert.deepEqual(harness.ctx.ui.notifications.at(-1), {
      message: "Sensitive data redacted from tool output",
      level: "info",
    });
  });

  it("redacts cyclic tool details without recursing indefinitely", async () => {
    const harness = createHarness();
    const details: Record<string, unknown> = { token: "apiKey=abcdefghijklmnopqrstuvwx" };
    details.self = details;

    const result = await emit(harness, "tool_result", {
      type: "tool_result",
      toolCallId: "custom-1",
      toolName: "custom",
      input: {},
      content: [],
      details,
      isError: false,
    });

    assert.equal(result.details.token, "apiKey=[REDACTED]");
    assert.equal(result.details.self, result.details);
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

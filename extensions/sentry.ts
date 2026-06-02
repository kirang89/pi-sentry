import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

type ReplacementFunction = (match: string, ...args: any[]) => string;
type Replacement = string | ReplacementFunction;

type SensitivePattern = {
  pattern: RegExp;
  replacement: Replacement;
};

type RedactionResult<T> = {
  value: T;
  modified: boolean;
};

type SentryMode = "strict" | "redact-only";

const DEFAULT_MODE: SentryMode = "redact-only";
const MAX_REDACTION_DEPTH = 8;
const SENTRY_MODES = new Set<SentryMode>(["strict", "redact-only"]);

const SECRET_KEY_FRAGMENT =
  "(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|client[_-]?secret|secret(?:[_-]?access[_-]?key)?|token|password|passwd|pwd|private[_-]?key)";

const quotedSecretValuePattern = new RegExp(
  `((?:^|[\\s{,;])['"]?[\\w.-]*${SECRET_KEY_FRAGMENT}[\\w.-]*['"]?\\s*[:=]\\s*)(['"])(?:\\\\.|(?!\\2)[^\\\\\\r\\n]){8,}\\2`,
  "gim",
);

const unquotedSecretValuePattern = new RegExp(
  `((?:^|[\\s{,;])['"]?[\\w.-]*${SECRET_KEY_FRAGMENT}[\\w.-]*['"]?\\s*[:=]\\s*)([^\\s'",}\\]]{8,})`,
  "gim",
);

const bashSensitiveReadCommands =
  /(?:^|[;&|]\s*)(?:cat|less|more|head|tail|grep|rg|awk|sed|strings|xxd|hexdump|base64|python3?|node|perl|ruby)\b/i;

const bashSecretDumpCommands =
  /(?:^|[;&|]\s*)(?:env|printenv|set|export\s+-p|gh\s+auth\s+token|npm\s+token|kubectl\s+config\s+view\s+--raw|gcloud\s+auth\s+application-default\s+print-access-token|aws\s+configure\s+export-credentials|security\s+find-generic-password\b.*\s-w\b|pass\s+show)\b/i;

export const sensitivePatterns: SensitivePattern[] = [
  { pattern: /\b(sk-ant-[a-zA-Z0-9_-]{20,})\b/g, replacement: "[ANTHROPIC_KEY_REDACTED]" },
  { pattern: /\b(sk-or-v1-[a-zA-Z0-9_-]{20,})\b/g, replacement: "[OPENROUTER_KEY_REDACTED]" },
  { pattern: /\b(sk-(?:proj|svcacct)-[a-zA-Z0-9_-]{20,})\b/g, replacement: "[OPENAI_KEY_REDACTED]" },
  { pattern: /\b(sk-[a-zA-Z0-9_-]{20,})\b/g, replacement: "[OPENAI_KEY_REDACTED]" },
  { pattern: /\b(AIza[a-zA-Z0-9_-]{30,})\b/g, replacement: "[GOOGLE_KEY_REDACTED]" },
  { pattern: /\b(cf(?:k|ut|at)_[a-zA-Z0-9_-]{41,})\b/g, replacement: "[CLOUDFLARE_TOKEN_REDACTED]" },
  { pattern: /\b(npm_[a-zA-Z0-9]{20,})\b/g, replacement: "[NPM_TOKEN_REDACTED]" },
  { pattern: /\b(glpat-[a-zA-Z0-9_-]{20,})\b/g, replacement: "[GITLAB_TOKEN_REDACTED]" },
  { pattern: /\b(gh[pousr]_[a-zA-Z0-9]{36,})\b/g, replacement: "[GITHUB_TOKEN_REDACTED]" },
  { pattern: /\b(github_pat_[a-zA-Z0-9_]{30,})\b/g, replacement: "[GITHUB_TOKEN_REDACTED]" },
  { pattern: /\b(xox[baprs]-[a-zA-Z0-9-]{10,})\b/g, replacement: "[SLACK_TOKEN_REDACTED]" },
  { pattern: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16})\b/g, replacement: "[AWS_ACCESS_KEY_REDACTED]" },
  { pattern: /\b(?:sk|rk)_live_[a-zA-Z0-9]{16,}\b/g, replacement: "[STRIPE_KEY_REDACTED]" },
  { pattern: /\bSG\.[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}\b/g, replacement: "[SENDGRID_KEY_REDACTED]" },
  { pattern: /\blin_api_[a-zA-Z0-9]{20,}\b/g, replacement: "[LINEAR_KEY_REDACTED]" },
  {
    pattern: quotedSecretValuePattern,
    replacement: (_match, prefix, quote) => `${String(prefix)}${String(quote)}[REDACTED]${String(quote)}`,
  },
  { pattern: unquotedSecretValuePattern, replacement: "$1[REDACTED]" },
  { pattern: /\b(bearer)\s+([a-zA-Z0-9._~+/=-]{16,})\b/gi, replacement: "Bearer [REDACTED]" },
  {
    pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g,
    replacement: "[JWT_REDACTED]",
  },
  { pattern: /([a-z][a-z0-9+.-]*:\/\/[^:\s/@]+:)[^@\s]+(@)/gi, replacement: "$1[REDACTED]$2" },
  {
    pattern:
      /-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/gi,
    replacement: "[PRIVATE_KEY_REDACTED]",
  },
];

const sensitiveFilePatterns = [
  /(^|\/)\.env$/i,
  /(^|\/)\.env\.[^/]+$/i,
  /(^|\/)\.dev\.vars($|\.[^/]+$)/i,
  /(^|\/)secrets?($|[./_-])/i,
  /(^|\/)credentials?($|[./_-])/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.pypirc$/i,
  /(^|\/)\.netrc$/i,
  /(^|\/)\.dockercfg$/i,
  /(^|\/)\.docker\/config\.json$/i,
  /(^|\/)\.kube\/config$/i,
  /(^|\/)\.aws\/(credentials|config)$/i,
  /(^|\/)\.gcloud\/application_default_credentials\.json$/i,
  /(^|\/)\.ssh\/id_[^/]+$/i,
  /(^|\/)terraform\.tfstate(\.backup)?$/i,
  /\.tfvars(\.json)?$/i,
  /(^|\/)service[-_]?account[^/]*\.json$/i,
  /\.(pem|p12|pfx)$/i,
  /(^|\/)[^/]*private[^/]*\.key$/i,
];

const nonSensitiveExampleFilePatterns = [
  /(^|\/)\.env\.(example|sample|template)$/i,
  /(^|\/)[^/]*(example|sample|template)[^/]*\.(env|json|ya?ml|toml|tfvars)$/i,
  /(^|\/)(secrets?|credentials?)\.example\.(json|ya?ml|toml)$/i,
];

export function redactText(
  text: string,
  patterns: SensitivePattern[] = sensitivePatterns,
): { text: string; modified: boolean } {
  let result = text;
  let modified = false;

  for (const { pattern, replacement } of patterns) {
    const redacted =
      typeof replacement === "function"
        ? result.replace(pattern, replacement)
        : result.replace(pattern, replacement);
    if (redacted !== result) {
      modified = true;
      result = redacted;
    }
  }

  return { text: result, modified };
}

export function normalizePathForSentry(path: string): string {
  return path.replace(/^@/, "").replace(/\\/g, "/");
}

export function isSensitivePath(path: string): boolean {
  const normalized = normalizePathForSentry(path);
  if (nonSensitiveExampleFilePatterns.some((pattern) => pattern.test(normalized))) return false;
  return sensitiveFilePatterns.some((pattern) => pattern.test(normalized));
}

export function isSensitiveBashCommand(command: string): boolean {
  // We block env/auth dump commands outright because their purpose is to expose credentials.
  if (bashSecretDumpCommands.test(command)) return true;

  // We only block general read/filter commands when they mention a sensitive path. This avoids
  // breaking normal grep/rg usage while closing the common `cat .env` bypass.
  return bashSensitiveReadCommands.test(command) && containsSensitivePathReference(command);
}

export function containsSecretLikeText(text: string): boolean {
  return redactText(text).modified;
}

function containsSensitivePathReference(text: string): boolean {
  return extractPathLikeTokens(text).some(isSensitivePath);
}

function extractPathLikeTokens(text: string): string[] {
  return text
    .split(/[\s'"`]+/)
    .map((token) => token.replace(/^[({[]+|[),;\]}]+$/g, ""))
    .filter(Boolean);
}

function redactUnknownValue(
  value: unknown,
  depth = 0,
  cache = new WeakMap<object, RedactionResult<unknown>>(),
): RedactionResult<unknown> {
  if (typeof value === "string") {
    const redacted = redactText(value);
    return { value: redacted.text, modified: redacted.modified };
  }

  if (value === null || typeof value !== "object" || depth >= MAX_REDACTION_DEPTH) {
    return { value, modified: false };
  }

  const cached = cache.get(value);
  if (cached) return cached;

  if (Array.isArray(value)) {
    const next: unknown[] = [];
    const result: RedactionResult<unknown> = { value: next, modified: false };
    cache.set(value, result);

    let modified = false;
    for (const item of value) {
      const redacted = redactUnknownValue(item, depth + 1, cache);
      if (redacted.modified) modified = true;
      next.push(redacted.value);
    }

    result.modified = modified;
    result.value = modified ? next : value;
    return result;
  }

  const current = value as Record<string, unknown>;
  const next: Record<string, unknown> = {};
  const result: RedactionResult<unknown> = { value: next, modified: false };
  cache.set(value, result);

  let modified = false;
  for (const [key, child] of Object.entries(current)) {
    if (key === "data" && typeof child === "string" && current.type === "image") {
      next[key] = child;
      continue;
    }
    // Cache redacted objects so repeated references reuse the safe copy instead of leaking
    // the original object through a later reference.
    const redacted = redactUnknownValue(child, depth + 1, cache);
    if (redacted.modified) modified = true;
    next[key] = redacted.value;
  }

  result.modified = modified;
  result.value = modified ? next : value;
  return result;
}

function redactMessage(message: unknown): RedactionResult<unknown> {
  if (!message || typeof message !== "object") return { value: message, modified: false };

  const current = message as Record<string, unknown>;
  const next: Record<string, unknown> = { ...current };
  let modified = false;

  if (typeof current.content === "string") {
    const redacted = redactText(current.content);
    if (redacted.modified) {
      next.content = redacted.text;
      modified = true;
    }
  } else if (Array.isArray(current.content)) {
    const redacted = redactContentBlocks(current.content);
    if (redacted.modified) {
      next.content = redacted.value;
      modified = true;
    }
  }

  for (const field of ["details", "command", "output", "errorMessage", "summary"] as const) {
    if (!(field in current)) continue;
    const redacted = redactUnknownValue(current[field]);
    if (redacted.modified) {
      next[field] = redacted.value;
      modified = true;
    }
  }

  return { value: modified ? next : message, modified };
}

function redactContentBlocks(blocks: unknown[]): RedactionResult<unknown[]> {
  let modified = false;
  const next = blocks.map((block) => {
    if (!block || typeof block !== "object") return block;
    const current = block as Record<string, unknown>;

    if (current.type === "image") return block;

    if (current.type === "text" && typeof current.text === "string") {
      const redacted = redactText(current.text);
      if (!redacted.modified) return block;
      modified = true;
      return { ...current, text: redacted.text };
    }

    if (current.type === "thinking" && typeof current.thinking === "string") {
      const redacted = redactText(current.thinking);
      if (!redacted.modified) return block;
      modified = true;
      return { ...current, thinking: redacted.text };
    }

    if (current.type === "toolCall") {
      const redacted = redactUnknownValue(current.arguments);
      if (!redacted.modified) return block;
      modified = true;
      return { ...current, arguments: redacted.value };
    }

    return block;
  });

  return { value: modified ? next : blocks, modified };
}

function toolInputAsText(input: unknown): string {
  if (typeof input === "string") return input;
  try {
    return JSON.stringify(input);
  } catch {
    return String(input);
  }
}

type SentryContext = {
  hasUI?: boolean;
  ui?: {
    notify(message: string, level: "info" | "warning" | "error"): void;
  };
};

function notify(
  ctx: SentryContext,
  message: string,
  level: "info" | "warning" | "error" = "info",
) {
  if (ctx.hasUI) ctx.ui?.notify(message, level);
}

function blockRiskyOperation(ctx: SentryContext, reason: string) {
  notify(ctx, reason, "warning");
  return { block: true, reason };
}

function parseSentryMode(input: string): SentryMode | undefined {
  const mode = input.trim();
  return SENTRY_MODES.has(mode as SentryMode) ? (mode as SentryMode) : undefined;
}

function blockedBashResult(ctx: SentryContext, reason: string) {
  notify(ctx, reason, "warning");
  return {
    result: {
      output: reason,
      exitCode: 1,
      cancelled: false,
      truncated: false,
    },
  };
}

function isSensitiveGrepInput(input: Record<string, unknown>): boolean {
  return [input.path, input.glob].some((value) => typeof value === "string" && isSensitivePath(value));
}

function getSensitiveFileMutationPath(toolName: string, input: Record<string, unknown>): string | undefined {
  if (toolName !== "edit" && toolName !== "write") return undefined;
  return typeof input.path === "string" && isSensitivePath(input.path) ? input.path : undefined;
}

/**
 * Filter or block sensitive data before it reaches the model or long-lived session history.
 */
export default function (pi: ExtensionAPI) {
  let mode = DEFAULT_MODE;

  pi.registerCommand("sentry", {
    description: "Show or set pi-sentry mode: strict or redact-only",
    handler: async (args, ctx) => {
      if (!args.trim()) {
        notify(ctx, `pi-sentry mode: ${mode}`, "info");
        return;
      }

      const nextMode = parseSentryMode(args);
      if (!nextMode) {
        notify(ctx, "Usage: /sentry strict | /sentry redact-only", "error");
        return;
      }

      mode = nextMode;
      notify(ctx, `pi-sentry mode set to ${mode}`, "info");
    },
  });

  pi.on("input", async (event, ctx) => {
    const redacted = redactText(event.text);
    if (!redacted.modified) return { action: "continue" };

    notify(ctx, "Sensitive data redacted from user input", "warning");
    return { action: "transform", text: redacted.text, images: event.images };
  });

  pi.on("message_end", async (event, ctx) => {
    const redacted = redactMessage(event.message);
    if (!redacted.modified) return undefined;

    notify(ctx, "Sensitive data redacted from session message", "info");
    return { message: redacted.value as typeof event.message };
  });

  pi.on("tool_call", async (event, ctx) => {
    if (mode === "redact-only") return undefined;

    if (event.toolName === "read" && typeof event.input.path === "string" && isSensitivePath(event.input.path)) {
      return blockRiskyOperation(ctx, `Blocked read of sensitive file: ${event.input.path}`);
    }

    const sensitiveMutationPath = getSensitiveFileMutationPath(event.toolName, event.input);
    if (sensitiveMutationPath) {
      return blockRiskyOperation(ctx, `Blocked ${event.toolName} of sensitive file: ${sensitiveMutationPath}`);
    }

    if (event.toolName === "grep" && isSensitiveGrepInput(event.input)) {
      return blockRiskyOperation(ctx, "Blocked grep of sensitive path or glob");
    }

    if (event.toolName === "bash" && typeof event.input.command === "string" && isSensitiveBashCommand(event.input.command)) {
      return blockRiskyOperation(ctx, "Blocked bash command likely to expose secrets");
    }

    // If a tool argument contains a secret literal, executing it would persist the secret in
    // tool-call metadata and often in shell history. Block instead of rewriting arguments,
    // because redaction could silently change command semantics.
    if (containsSecretLikeText(toolInputAsText(event.input))) {
      return blockRiskyOperation(ctx, `Blocked ${event.toolName} call containing secret-like text`);
    }

    return undefined;
  });

  pi.on("user_bash", async (event, ctx) => {
    if (mode === "redact-only") return undefined;
    if (!isSensitiveBashCommand(event.command)) return undefined;

    return blockedBashResult(ctx, "Blocked user bash command likely to expose secrets");
  });

  pi.on("tool_result", async (event, ctx) => {
    if (event.toolName === "read" && typeof event.input.path === "string" && isSensitivePath(event.input.path)) {
      notify(ctx, `Redacted contents of sensitive file: ${event.input.path}`, "info");
      return {
        content: [{ type: "text", text: `[Contents of ${event.input.path} redacted for security]` }],
      };
    }

    let wasModified = false;
    const content = event.content.map((item) => {
      if (item.type !== "text") return item;
      const redacted = redactText(item.text);
      if (redacted.modified) wasModified = true;
      return redacted.modified ? { ...item, text: redacted.text } : item;
    });

    const details = redactUnknownValue(event.details);
    if (details.modified) wasModified = true;

    if (!wasModified) return undefined;

    notify(ctx, "Sensitive data redacted from tool output", "info");
    return {
      content,
      ...(details.modified ? { details: details.value } : {}),
    };
  });
}

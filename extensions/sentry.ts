import { readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
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

type SentryMode = "strict" | "redact-only" | "off";

export type SentryConfig = {
  allowPaths: string[];
  blockPaths: string[];
};

const MODE_STRICT: SentryMode = "strict";
const MODE_REDACT_ONLY: SentryMode = "redact-only";
const MODE_OFF: SentryMode = "off";
const SENTRY_MODE_VALUES = [MODE_STRICT, MODE_REDACT_ONLY, MODE_OFF] as const;

const DEFAULT_MODE: SentryMode = MODE_REDACT_ONLY;
const SENTRY_MODES = new Set<SentryMode>(SENTRY_MODE_VALUES);
const EMPTY_SENTRY_CONFIG: SentryConfig = { allowPaths: [], blockPaths: [] };

const SENTRY_CONFIG_FILE_NAME = "pi-sentry.json";
const DEFAULT_PI_CONFIG_DIR_SEGMENTS = [".pi", "agent"] as const;
const SENTRY_COMMAND_NAME = "sentry";

const EVENT_SESSION_START = "session_start";
const EVENT_INPUT = "input";
const EVENT_MESSAGE_END = "message_end";
const EVENT_TOOL_CALL = "tool_call";
const EVENT_USER_BASH = "user_bash";
const EVENT_TOOL_RESULT = "tool_result";

const TOOL_READ = "read";
const TOOL_GREP = "grep";
const TOOL_BASH = "bash";
const TOOL_EDIT = "edit";
const TOOL_WRITE = "write";
const MUTATING_FILE_TOOLS = new Set([TOOL_EDIT, TOOL_WRITE]);

const CONTENT_TYPE_TEXT = "text";
const CONTENT_TYPE_IMAGE = "image";
const CONTENT_TYPE_THINKING = "thinking";
const CONTENT_TYPE_TOOL_CALL = "toolCall";
const FIELD_ARGUMENTS = "arguments";
const FIELD_DATA = "data";
const FIELD_TEXT = "text";
const FIELD_THINKING = "thinking";
const FIELD_TYPE = "type";
const REDACTABLE_MESSAGE_FIELDS = ["details", "command", "output", "errorMessage", "summary"] as const;
const SENTRY_COMMAND_DESCRIPTION = "Show or set pi-sentry mode: strict, redact-only, or off";

const NOTIFICATION_MESSAGES = {
  modeStatus: (mode: SentryMode) => `pi-sentry mode: ${mode}`,
  modeChanged: (mode: SentryMode) => `pi-sentry mode set to ${mode}`,
  modeUsage: `Usage: ${SENTRY_MODE_VALUES.map((mode) => `/${SENTRY_COMMAND_NAME} ${mode}`).join(" | ")}`,
  redactedUserInput: "Sensitive data redacted from user input",
  redactedSessionMessage: "Sensitive data redacted from session message",
  redactedToolOutput: "Sensitive data redacted from tool output",
  blockedUserBash: "Blocked user bash command likely to expose secrets",
  blockedGrep: "Blocked grep of sensitive path or glob",
  blockedBashTool: "Blocked bash command likely to expose secrets",
  blockedSecretToolCall: (toolName: string) => `Blocked ${toolName} call containing secret-like text`,
  blockedSensitiveRead: (path: string) => `Blocked read of sensitive file: ${path}`,
  blockedSensitiveMutation: (toolName: string, path: string) => `Blocked ${toolName} of sensitive file: ${path}`,
  redactedSensitiveFile: (path: string) => `Redacted contents of sensitive file: ${path}`,
  redactedSensitiveFileContents: (path: string) => `[Contents of ${path} redacted for security]`,
} as const;

const SECRET_KEY_FRAGMENT =
  "(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|client[_-]?secret|secret(?:[_-]?access[_-]?key)?|token|password|passwd|pwd|private[_-]?key|session[_-]?cookie)";

const quotedSecretValuePattern = new RegExp(
  `((?:^|[\\s{,;])['"]?[\\w.-]*${SECRET_KEY_FRAGMENT}[\\w.-]*['"]?\\s*[:=]\\s*)(['"])(?:\\\\.|(?!\\2)[^\\\\\\r\\n]){8,}\\2`,
  "gim",
);

const unquotedSecretValuePattern = new RegExp(
  `((?:^|[\\s{,;])['"]?[\\w.-]*${SECRET_KEY_FRAGMENT}[\\w.-]*['"]?\\s*[:=]\\s*)([^\\s'",}\\]\\[]{8,})`,
  "gim",
);

const bashSecretDumpCommands =
  /(?:^|[\s;&|])(?:env|printenv|set|export\s+-p|gh\s+auth\s+token|npm\s+token|kubectl\s+config\s+view\s+--raw|gcloud\s+auth\s+application-default\s+print-access-token|aws\s+configure\s+export-credentials|security\s+find-generic-password\b.*\s-w\b|pass\s+show)\b/i;

const SECRET_ENV_VAR_NAME = `[A-Za-z_][A-Za-z0-9_]*${SECRET_KEY_FRAGMENT}[A-Za-z0-9_]*`;
const SECRET_ENV_VAR_REFERENCE = `(?:\\$${SECRET_ENV_VAR_NAME}\\b|\\$\\{!?${SECRET_ENV_VAR_NAME}[^}]*\\})`;
const bashSecretEnvEchoCommands = new RegExp(
  `(?:^|[\\s;&|()'"])(?:echo|printf)\\b[^;&|]*${SECRET_ENV_VAR_REFERENCE}`,
  "i",
);

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
    // Redact full private-key blocks before generic key/value redaction can partially
    // replace only the first token (for example `PRIVATE_KEY=-----BEGIN ...`).
    pattern:
      /-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/gi,
    replacement: "[PRIVATE_KEY_REDACTED]",
  },
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
  /(^|\/)\.ssh($|\/)/i,
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

export function parseSentryConfig(value: unknown): SentryConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("pi-sentry config must be a JSON object");
  }

  const input = value as Record<string, unknown>;
  return {
    allowPaths: parsePathList(input.allowPaths, "allowPaths"),
    blockPaths: parsePathList(input.blockPaths, "blockPaths"),
  };
}

type LoadedSentryConfig = {
  config: SentryConfig;
  loaded: boolean;
};

export async function loadSentryConfig(configDir = getDefaultPiConfigDir()): Promise<SentryConfig> {
  return (await loadSentryConfigWithStatus(configDir)).config;
}

async function loadSentryConfigWithStatus(configDir: string): Promise<LoadedSentryConfig> {
  const configPath = getSentryConfigPath(configDir);

  try {
    const content = await readFile(configPath, "utf8");
    return { config: parseSentryConfig(JSON.parse(content)), loaded: true };
  } catch (error) {
    if (isMissingFileError(error)) return { config: EMPTY_SENTRY_CONFIG, loaded: false };
    throw new Error(`Failed to load ${configPath}: ${errorMessage(error)}`, { cause: error });
  }
}

export function isSensitivePath(path: string, config: SentryConfig = EMPTY_SENTRY_CONFIG): boolean {
  const normalized = normalizePathForSentry(path);

  // User rules intentionally override built-in defaults. If user rules conflict,
  // blocking wins because exposing a secret is harder to recover from than over-blocking.
  if (matchesConfiguredPath(normalized, config.blockPaths)) return true;
  if (matchesConfiguredPath(normalized, config.allowPaths)) return false;

  if (nonSensitiveExampleFilePatterns.some((pattern) => pattern.test(normalized))) return false;
  return sensitiveFilePatterns.some((pattern) => pattern.test(normalized));
}

export function isSensitiveBashCommand(command: string, config: SentryConfig = EMPTY_SENTRY_CONFIG): boolean {
  // Shell syntax is too flexible to identify only file-reading commands reliably. In strict
  // mode, conservatively block any command that references a sensitive path or secret source.
  return (
    bashSecretDumpCommands.test(command) ||
    bashSecretEnvEchoCommands.test(command) ||
    containsSensitivePathReference(command, config)
  );
}

export function containsSecretLikeText(text: string): boolean {
  return redactText(text).modified;
}

function containsSensitivePathReference(text: string, config: SentryConfig): boolean {
  return extractPathLikeTokens(expandShellSeparators(text)).some((token) => isSensitivePath(token, config));
}

function expandShellSeparators(text: string): string {
  return text.replace(/\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*/g, " ");
}

function extractPathLikeTokens(text: string): string[] {
  return text
    .split(/[\s'"`]+/)
    .map((token) => token.replace(/^[A-Za-z_][A-Za-z0-9_]*=/, ""))
    .map((token) => token.replace(/^[({[]+|[),;\]}]+$/g, ""))
    .filter(Boolean);
}

function parsePathList(value: unknown, fieldName: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${fieldName} must be an array of strings`);

  return value.map((item, index) => {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error(`${fieldName}[${index}] must be a non-empty string`);
    }
    return item.trim();
  });
}

function getDefaultPiConfigDir(): string {
  return process.env.PI_CODING_AGENT_DIR ?? join(homedir(), ...DEFAULT_PI_CONFIG_DIR_SEGMENTS);
}

function getSentryConfigPath(configDir = getDefaultPiConfigDir()): string {
  return join(configDir, SENTRY_CONFIG_FILE_NAME);
}

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function matchesConfiguredPath(path: string, patterns: string[]): boolean {
  const normalizedPath = normalizePathForSentry(path).replace(/^\.\//, "");
  const pathSegments = normalizedPath.split("/").filter(Boolean);

  return patterns.some((pattern) => {
    const normalizedPattern = normalizePathForSentry(pattern).replace(/^\.\//, "");
    if (!hasGlobSyntax(normalizedPattern) && !normalizedPattern.includes("/")) {
      return pathSegments.includes(normalizedPattern);
    }

    return globMatchesPath(normalizedPattern, normalizedPath);
  });
}

function hasGlobSyntax(pattern: string): boolean {
  return /[*?]/.test(pattern);
}

function globMatchesPath(pattern: string, path: string): boolean {
  const source = globToRegExpSource(pattern);
  const prefix = pattern.startsWith("/") ? "^" : "(^|.*/)";
  return new RegExp(`${prefix}${source}$`).test(path);
}

function globToRegExpSource(pattern: string): string {
  let source = "";

  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    const next = pattern[index + 1];

    if (char === "*" && next === "*") {
      if (pattern[index + 2] === "/") {
        source += "(?:.*/)?";
        index += 2;
        continue;
      }

      source += ".*";
      index += 1;
      continue;
    }

    if (char === "*") {
      source += "[^/]*";
      continue;
    }

    if (char === "?") {
      source += "[^/]";
      continue;
    }

    source += escapeRegExp(char ?? "");
  }

  return source;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

type RedactionCache = WeakMap<object, RedactionResult<unknown>>;

function redactUnknownValue(
  value: unknown,
  cache: RedactionCache = new WeakMap<object, RedactionResult<unknown>>(),
): RedactionResult<unknown> {
  if (typeof value === "string") return redactStringValue(value);
  if (!canRedactNestedValue(value)) return { value, modified: false };

  const cached = cache.get(value);
  if (cached) return cached;

  return Array.isArray(value)
    ? redactArrayValue(value, cache)
    : redactObjectValue(value as Record<string, unknown>, cache);
}

function redactStringValue(value: string): RedactionResult<string> {
  const redacted = redactText(value);
  return { value: redacted.text, modified: redacted.modified };
}

function canRedactNestedValue(value: unknown): value is object {
  return value !== null && typeof value === "object";
}

function redactArrayValue(value: unknown[], cache: RedactionCache): RedactionResult<unknown> {
  const next: unknown[] = [];
  const result: RedactionResult<unknown> = { value: next, modified: false };
  cache.set(value, result);

  let modified = false;
  for (const item of value) {
    const redacted = redactUnknownValue(item, cache);
    if (redacted.modified) modified = true;
    next.push(redacted.value);
  }

  result.modified = modified;
  result.value = modified ? next : value;
  return result;
}

function redactObjectValue(value: Record<string, unknown>, cache: RedactionCache): RedactionResult<unknown> {
  const next: Record<string, unknown> = {};
  const result: RedactionResult<unknown> = { value: next, modified: false };
  cache.set(value, result);

  let modified = false;
  for (const [key, child] of Object.entries(value)) {
    if (shouldPreserveImageData(value, key, child)) {
      next[key] = child;
      continue;
    }

    // Cache redacted objects so repeated references reuse the safe copy instead of leaking
    // the original object through a later reference.
    const redacted = redactUnknownValue(child, cache);
    if (redacted.modified) modified = true;
    next[key] = redacted.value;
  }

  result.modified = modified;
  result.value = modified ? next : value;
  return result;
}

function shouldPreserveImageData(current: Record<string, unknown>, key: string, child: unknown): boolean {
  return key === FIELD_DATA && typeof child === "string" && current[FIELD_TYPE] === CONTENT_TYPE_IMAGE;
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

  for (const field of REDACTABLE_MESSAGE_FIELDS) {
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
    const redacted = redactContentBlock(block);
    if (redacted.modified) modified = true;
    return redacted.value;
  });

  return { value: modified ? next : blocks, modified };
}

function redactContentBlock(block: unknown): RedactionResult<unknown> {
  if (!block || typeof block !== "object") return { value: block, modified: false };

  const current = block as Record<string, unknown>;
  if (current[FIELD_TYPE] === CONTENT_TYPE_IMAGE) return { value: block, modified: false };
  if (current[FIELD_TYPE] === CONTENT_TYPE_TEXT) return redactContentBlockTextField(current, FIELD_TEXT);
  if (current[FIELD_TYPE] === CONTENT_TYPE_THINKING) return redactContentBlockTextField(current, FIELD_THINKING);
  if (current[FIELD_TYPE] === CONTENT_TYPE_TOOL_CALL) return redactToolCallContentBlock(current);

  return { value: block, modified: false };
}

function redactContentBlockTextField(
  block: Record<string, unknown>,
  field: typeof FIELD_TEXT | typeof FIELD_THINKING,
): RedactionResult<unknown> {
  if (typeof block[field] !== "string") return { value: block, modified: false };

  const redacted = redactText(block[field]);
  return redacted.modified ? { value: { ...block, [field]: redacted.text }, modified: true } : { value: block, modified: false };
}

function redactToolCallContentBlock(block: Record<string, unknown>): RedactionResult<unknown> {
  const redacted = redactUnknownValue(block[FIELD_ARGUMENTS]);
  return redacted.modified
    ? { value: { ...block, [FIELD_ARGUMENTS]: redacted.value }, modified: true }
    : { value: block, modified: false };
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

const SENSITIVE_GLOB_EXAMPLES = [
  ".env",
  ".env.local",
  ".dev.vars",
  "secrets/value",
  "credentials/value",
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".dockercfg",
  ".docker/config.json",
  ".kube/config",
  ".aws/credentials",
  ".gcloud/application_default_credentials.json",
  ".ssh/config",
  "terraform.tfstate",
  "terraform.tfstate.backup",
  "terraform.tfvars",
  "terraform.tfvars.json",
  "service-account.json",
  "private.key",
  "certificate.pem",
];

function isSensitiveGrepInput(input: Record<string, unknown>, config: SentryConfig): boolean {
  return (
    (typeof input.path === "string" && isSensitivePath(input.path, config)) ||
    (typeof input.glob === "string" && isSensitiveGlob(input.glob, config))
  );
}

function isSensitiveGlob(glob: string, config: SentryConfig): boolean {
  if (isSensitivePath(glob, config)) return true;
  const normalizedGlob = normalizePathForSentry(glob);
  return SENSITIVE_GLOB_EXAMPLES.some(
    (path) => isSensitivePath(path, config) && globMatchesPath(normalizedGlob, path),
  );
}

async function getSensitiveFileMutationPath(
  toolName: string,
  input: Record<string, unknown>,
  config: SentryConfig,
): Promise<string | undefined> {
  if (!MUTATING_FILE_TOOLS.has(toolName) || typeof input.path !== "string") return undefined;
  return (await isSensitiveFilePath(input.path, config)) ? input.path : undefined;
}

async function isSensitiveFilePath(path: string, config: SentryConfig): Promise<boolean> {
  if (isSensitivePath(path, config)) return true;

  const resolved = await resolvePathThroughExistingAncestor(path);
  return resolved !== undefined && isSensitivePath(resolved, config);
}

async function resolvePathThroughExistingAncestor(path: string): Promise<string | undefined> {
  let candidate = path;
  const missingSegments: string[] = [];

  while (true) {
    try {
      return join(await realpath(candidate), ...missingSegments);
    } catch (error) {
      if (!isMissingFileError(error)) return undefined;

      const parent = dirname(candidate);
      if (parent === candidate) return undefined;
      missingSegments.unshift(basename(candidate));
      candidate = parent;
    }
  }
}

type SentryState = {
  mode: SentryMode;
  config: SentryConfig;
  configPath: string;
  configLoaded: boolean;
};

function handleSentryCommand(args: string, ctx: SentryContext, state: SentryState): void {
  if (!args.trim()) {
    const configStatus = state.configLoaded ? `✓ ${state.configPath} loaded` : `✗ ${state.configPath} not loaded`;
    notify(ctx, `${NOTIFICATION_MESSAGES.modeStatus(state.mode)}\n${configStatus}`, "info");
    return;
  }

  const nextMode = parseSentryMode(args);
  if (!nextMode) {
    notify(ctx, NOTIFICATION_MESSAGES.modeUsage, "error");
    return;
  }

  state.mode = nextMode;
  notify(ctx, NOTIFICATION_MESSAGES.modeChanged(state.mode), "info");
}

async function loadConfigForSession(ctx: SentryContext, state: SentryState): Promise<void> {
  state.configPath = getSentryConfigPath();
  try {
    const loaded = await loadSentryConfigWithStatus(getDefaultPiConfigDir());
    state.config = loaded.config;
    state.configLoaded = loaded.loaded;
  } catch (error) {
    state.config = EMPTY_SENTRY_CONFIG;
    state.configLoaded = false;
    notify(ctx, errorMessage(error), "warning");
  }
}

function handleInput(event: any, ctx: SentryContext, mode: SentryMode) {
  if (mode === MODE_OFF) return { action: "continue" as const };

  const redacted = redactText(event.text);
  if (!redacted.modified) return { action: "continue" as const };

  notify(ctx, NOTIFICATION_MESSAGES.redactedUserInput, "warning");
  return { action: "transform" as const, text: redacted.text, images: event.images };
}

function handleMessageEnd(event: any, ctx: SentryContext, mode: SentryMode) {
  if (mode === MODE_OFF) return undefined;

  const redacted = redactMessage(event.message);
  if (!redacted.modified) return undefined;

  notify(ctx, NOTIFICATION_MESSAGES.redactedSessionMessage, "info");
  return { message: redacted.value as typeof event.message };
}

async function handleToolCall(event: any, ctx: SentryContext, state: SentryState) {
  if (state.mode !== MODE_STRICT) return undefined;

  const blockReason = await getToolCallBlockReason(event, state.config);
  return blockReason ? blockRiskyOperation(ctx, blockReason) : undefined;
}

async function getToolCallBlockReason(event: any, config: SentryConfig): Promise<string | undefined> {
  if (
    event.toolName === TOOL_READ &&
    typeof event.input.path === "string" &&
    (await isSensitiveFilePath(event.input.path, config))
  ) {
    return NOTIFICATION_MESSAGES.blockedSensitiveRead(event.input.path);
  }

  const sensitiveMutationPath = await getSensitiveFileMutationPath(event.toolName, event.input, config);
  if (sensitiveMutationPath) {
    return NOTIFICATION_MESSAGES.blockedSensitiveMutation(event.toolName, sensitiveMutationPath);
  }

  if (event.toolName === TOOL_GREP && isSensitiveGrepInput(event.input, config)) {
    return NOTIFICATION_MESSAGES.blockedGrep;
  }

  if (event.toolName === TOOL_BASH && typeof event.input.command === "string" && isSensitiveBashCommand(event.input.command, config)) {
    return NOTIFICATION_MESSAGES.blockedBashTool;
  }

  // If a tool argument contains a secret literal, executing it would persist the secret in
  // tool-call metadata and often in shell history. Block instead of rewriting arguments,
  // because redaction could silently change command semantics.
  if (containsSecretLikeText(toolInputAsText(event.input))) {
    return NOTIFICATION_MESSAGES.blockedSecretToolCall(event.toolName);
  }

  return undefined;
}

function handleUserBash(event: any, ctx: SentryContext, state: SentryState) {
  if (state.mode !== MODE_STRICT) return undefined;
  if (!isSensitiveBashCommand(event.command, state.config)) return undefined;

  return blockedBashResult(ctx, NOTIFICATION_MESSAGES.blockedUserBash);
}

async function handleToolResult(event: any, ctx: SentryContext, state: SentryState): Promise<any> {
  if (state.mode === MODE_OFF) return undefined;

  const sensitiveReadResult = await redactSensitiveReadResult(event, ctx, state.config);
  if (sensitiveReadResult) return sensitiveReadResult;

  const redacted = redactToolResultPayload(event);
  if (!redacted.modified) return undefined;

  notify(ctx, NOTIFICATION_MESSAGES.redactedToolOutput, "info");
  return redacted.value;
}

async function redactSensitiveReadResult(event: any, ctx: SentryContext, config: SentryConfig): Promise<any> {
  if (
    event.toolName !== TOOL_READ ||
    typeof event.input.path !== "string" ||
    !(await isSensitiveFilePath(event.input.path, config))
  ) {
    return undefined;
  }

  notify(ctx, NOTIFICATION_MESSAGES.redactedSensitiveFile(event.input.path), "info");
  return {
    content: [{ type: "text", text: NOTIFICATION_MESSAGES.redactedSensitiveFileContents(event.input.path) }],
  };
}

function redactToolResultPayload(event: any): RedactionResult<any> {
  let modified = false;
  const content = redactToolResultContent(event.content);
  if (content.modified) modified = true;

  const details = redactUnknownValue(event.details);
  if (details.modified) modified = true;

  return {
    value: {
      content: content.value,
      ...(details.modified ? { details: details.value } : {}),
    },
    modified,
  };
}

function redactToolResultContent(contentBlocks: any[]): RedactionResult<any[]> {
  let modified = false;
  const value = contentBlocks.map((item) => {
    if (item.type !== "text") return item;

    const redacted = redactText(item.text);
    if (!redacted.modified) return item;

    modified = true;
    return { ...item, text: redacted.text };
  });

  return { value: modified ? value : contentBlocks, modified };
}

/**
 * Filter or block sensitive data before it reaches the model or long-lived session history.
 */
export default function (pi: ExtensionAPI) {
  const state: SentryState = {
    mode: DEFAULT_MODE,
    config: EMPTY_SENTRY_CONFIG,
    configPath: getSentryConfigPath(),
    configLoaded: false,
  };

  pi.on(EVENT_SESSION_START, async (_event, ctx) => loadConfigForSession(ctx, state));

  pi.registerCommand(SENTRY_COMMAND_NAME, {
    description: SENTRY_COMMAND_DESCRIPTION,
    handler: async (args, ctx) => handleSentryCommand(args, ctx, state),
  });

  pi.on(EVENT_INPUT, async (event, ctx) => handleInput(event, ctx, state.mode));
  pi.on(EVENT_MESSAGE_END, async (event, ctx) => handleMessageEnd(event, ctx, state.mode));
  pi.on(EVENT_TOOL_CALL, async (event, ctx) => handleToolCall(event, ctx, state));
  pi.on(EVENT_USER_BASH, async (event, ctx) => handleUserBash(event, ctx, state));
  pi.on(EVENT_TOOL_RESULT, async (event, ctx) => handleToolResult(event, ctx, state));
}

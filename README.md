# pi-sentry

`pi-sentry` is a Pi extension package that reduces accidental secret exposure. It combines pre-execution gates with output/session redaction so secrets are less likely to reach the model, the TUI, or persistent session history.

## Install

From GitHub:

```bash
pi install git:https://github.com/kirang89/pi-sentry.git
# or pin a tag/commit
pi install git:https://github.com/kirang89/pi-sentry.git@v0.1.0
```

From this local checkout:

```bash
pi install /Users/kiran/personal/pi-sentry
```

For one-off testing without installing:

```bash
pi -e /Users/kiran/personal/pi-sentry
```

Reload an active Pi session with `/reload` after installing.

## What it protects

### Sensitive file reads

Blocks `read` access to files such as `.env`, `.npmrc`, `.aws/credentials`, `.kube/config`, `.docker/config.json`, private keys, Terraform state/vars, and service-account JSON files.

### Shell exfiltration

Blocks common `bash` paths such as `cat .env`, `rg token ~/.aws/credentials`, `printenv`, `gh auth token`, and `kubectl config view --raw`.

### Literal secrets in tool calls

Blocks tool calls containing secret-like values instead of rewriting arguments, because rewriting commands can silently change behavior.

### Tool output leakage

Redacts secrets from tool outputs, including stderr and error details.

### Session history leakage

Redacts text fields in session messages and recursively redacts string fields in tool `details` metadata while skipping image data.

## Redaction coverage

The redactor covers common formats:

- JSON: `{ "token": "..." }`
- YAML/env: `AWS_SECRET_ACCESS_KEY=...`, `password: ...`
- snake_case and camelCase keys: `db_password`, `dbPassword`, `stripeApiKey`
- provider tokens: OpenAI, Anthropic, OpenRouter, Google, Cloudflare, npm, GitHub, GitLab, Slack, Stripe, SendGrid, Linear
- bearer tokens and JWTs
- URLs with userinfo passwords, including database URLs
- private key blocks

## Modes

The current default is redact-only mode, implemented as a constant in `extensions/sentry.ts`:

```ts
const DEFAULT_MODE = "redact-only";
```

Switch modes inside Pi with `/sentry strict` or `/sentry redact-only`.

Available modes:

- `strict`: block known risky reads/commands before execution, and redact any secrets that still appear in inputs, outputs, or session messages.
- `redact-only`: allow tool calls to run, but redact sensitive data from inputs, outputs, and session messages.

## Development

```bash
npm install
npm test
npm run typecheck
```


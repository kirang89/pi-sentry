# pi-sentry

`pi-sentry` is a Pi extension package that reduces accidental secret exposure. It combines pre-execution gates with output/session redaction so secrets are less likely to reach the model, the TUI, or persistent session history.

## Install

From this local checkout:

```bash
pi install /Users/kiran/personal/pi-sentry
```

After publishing to GitHub:

```bash
pi install git:github.com/<user>/pi-sentry
# or pin a tag/commit
pi install git:github.com/<user>/pi-sentry@v0.1.0
```

For one-off testing without installing:

```bash
pi -e /Users/kiran/personal/pi-sentry
```

Reload an active Pi session with `/reload` after installing.

## What it protects

- Blocks `read` tool access to sensitive files such as `.env`, `.npmrc`, `.aws/credentials`, `.kube/config`, `.docker/config.json`, private keys, Terraform state/vars, and service-account JSON files.
- Blocks common `bash` exfiltration paths such as `cat .env`, `rg token ~/.aws/credentials`, `printenv`, `gh auth token`, and `kubectl config view --raw`.
- Blocks tool calls containing literal secret-like values instead of rewriting them, because rewriting command arguments can silently change behavior.
- Redacts secrets from tool outputs, including error outputs.
- Redacts text fields in session messages so assistant tool-call arguments and user/bash messages are less likely to persist secrets.
- Recursively redacts string fields in tool `details` metadata while skipping image data.

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

The current default is strict mode, implemented as a constant in `extensions/sentry.ts`:

```ts
const DEFAULT_MODE = "strict";
```

Available modes:

- `strict`: block risky reads/commands and redact outputs.
- `warn`: ask for confirmation when a UI is available, otherwise block.
- `redact-only`: preserve the original filter-output behavior and only redact results/messages.

## Development

```bash
npm install
npm test
npm run typecheck
```

## Limitations

No regex-only secret detector is perfect. This extension is a defense-in-depth layer, not a substitute for avoiding secret material in prompts, commands, repositories, logs, or generated files.

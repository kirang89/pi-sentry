# pi-sentry

pi-sentry is a pi extension that helps protect credentials and secrets.

By default, it redacts secrets from inputs, tool output, and session history. In strict mode, it also blocks risky file reads, searches, commands, and tool calls. You can turn it off when needed.

## What it protects

- **Sensitive file reads**: in strict mode, blocks access to files like `.env`, `.npmrc`, `.aws/credentials`, `.kube/config`, `.docker/config.json`, private keys, Terraform state/vars, and service-account JSON files.
- **Shell commands**: in strict mode, blocks commands that may expose secrets, such as `cat .env`, `rg token ~/.aws/credentials`, `printenv`, `gh auth token`, and `kubectl config view --raw`.
- **Secrets in tool calls**: in strict mode, blocks tool calls that contain secret-like values. It blocks them instead of rewriting them, because rewriting a command can change what it does.
- **Sensitive path search**: in strict mode, blocks `grep` searches that target sensitive paths or globs.
- **Tool output**: redacts secrets from tool output, including stderr and error details.
- Session history: redacts secrets from session text, tool-call arguments, and tool result details.

## Install

Install from GitHub:

```bash
pi install git:https://github.com/kirang89/pi-sentry.git
# or pin a tag/commit
pi install git:https://github.com/kirang89/pi-sentry.git@v0.1.0
```

Try it without installing:

```bash
pi -e git:https://github.com/kirang89/pi-sentry.git
```

Reload an active Pi session with `/reload` after installing.

## Usage

Use `/sentry` inside the agent to view or change the mode:

```text
/sentry
/sentry strict
/sentry redact-only
/sentry off
```

- `/sentry` shows the current mode.
- `/sentry strict` blocks risky actions and redacts secrets.
- `/sentry redact-only` allows actions but redacts secrets. This is the default.
- `/sentry off` disables pi-sentry.

## What it redacts

pi-sentry redacts common secret formats:

- JSON: `{ "token": "..." }`
- YAML/env: `AWS_SECRET_ACCESS_KEY=...`, `password: ...`
- snake_case and camelCase keys: `db_password`, `dbPassword`, `stripeApiKey`
- provider tokens: OpenAI, Anthropic, OpenRouter, Google, GitHub, etc.
- bearer tokens and JWTs
- passwords in URLs, including database URLs
- private key blocks

## Modes

The default mode is `redact-only`.

- `strict`: block risky file reads, searches, file changes, and commands. Also redact secrets from inputs, outputs, and session messages.
- `redact-only`: allow tool calls and user bash commands, but redact secrets from inputs, outputs, and session messages.
- `off`: disable all pi-sentry blocking and redaction.

## Development

```bash
npm install
npm run lint
npm run typecheck
npm test
```

# pi-sentry

[![CI](https://github.com/kirang89/pi-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/kirang89/pi-sentry/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@kiranpg/pi-sentry.svg)](https://www.npmjs.com/package/@kiranpg/pi-sentry)

pi-sentry is a pi extension that helps protect credentials and secrets.

By default, it redacts secrets from inputs, tool output, and session history. In strict mode, it also blocks risky file reads, searches, commands, and tool calls. You can turn it off when needed.

## Overview

pi-sentry protects against:

- **Sensitive file reads**: in strict mode, blocks access to files and directories like `.env`, `.npmrc`, `.aws/credentials`, `.kube/config`, `.ssh/`, `.docker/config.json`, private keys, Terraform state/vars, and service-account JSON files.
- **Sensitive shell commands**: in strict mode, blocks commands that may expose secrets, such as `cat .env`, `echo $OPENAI_API_KEY`, scripts that echo secret env vars, `rg token ~/.aws/credentials`, `printenv`, `gh auth token`, and `kubectl config view --raw`.
- **Secrets in tool calls**: in strict mode, blocks tool calls that contain secret-like values.
- **Sensitive path search**: in strict mode, blocks `grep` searches that target sensitive paths or globs.
- **Secrets in tool output**: redacts secrets from tool output, including stderr and error details.
- **Session history**: redacts secrets from session text, tool-call arguments, and tool result details.

pi-sentry redacts common secret formats:

- JSON: `{ "token": "..." }`
- YAML/env: `AWS_SECRET_ACCESS_KEY=...`, `password: ...`
- snake_case and camelCase keys: `db_password`, `dbPassword`, `stripeApiKey`
- provider tokens: OpenAI, Anthropic, OpenRouter, Google, GitHub, etc.
- bearer tokens and JWTs
- passwords in URLs, including database URLs
- private key blocks, including env values like `PRIVATE_KEY=...`
- session cookies, such as `SESSION_COOKIE=...`

## Install

Install from npm:

```bash
pi install npm:@kiranpg/pi-sentry
```

Install from GitHub:

```bash
pi install git:https://github.com/kirang89/pi-sentry.git
# or pin a tag/commit
pi install git:https://github.com/kirang89/pi-sentry.git@v0.1.0
```

Try it without installing:

```bash
pi -e npm:@kiranpg/pi-sentry
# or
pi -e git:https://github.com/kirang89/pi-sentry.git
```

Reload an active Pi session with `/reload` after installing.

## Usage

Use `/sentry` inside the agent to view or change the mode:
- `/sentry` shows the current mode.
- `/sentry strict` blocks risky actions and redacts secrets.
- `/sentry redact-only` allows actions but redacts secrets. This is the default.
- `/sentry off` disables pi-sentry.

## Config

Create `~/.pi/agent/pi-sentry.json` to add custom path rules:

```json
{
  "allowPaths": [".env.local.example"],
  "blockPaths": ["private/**", "*.secret.json"]
}
```

- `allowPaths` allows paths that pi-sentry would otherwise block.
- `blockPaths` blocks paths that pi-sentry would otherwise allow.
- User rules override built-in rules.
- If a path matches both `allowPaths` and `blockPaths`, pi-sentry blocks it.
- Plain filenames like `.env` match any path segment.
- Glob patterns support `*`, `**`, and `?`.

Run `/reload` after changing this file.

## Development

```bash
npm install
npm run lint
npm run typecheck
npm test
```

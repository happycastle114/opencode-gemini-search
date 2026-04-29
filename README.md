# @happycastle/opencode-gemini-search

> Privacy-hardened Google Gemini web-search tool for [OpenCode](https://github.com/sst/opencode), with mandatory inline citations and zero data leakage.

[![CI](https://github.com/happycastle114/opencode-gemini-search/actions/workflows/ci.yml/badge.svg)](https://github.com/happycastle114/opencode-gemini-search/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@happycastle/opencode-gemini-search.svg)](https://www.npmjs.com/package/@happycastle/opencode-gemini-search)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What it does

Registers a `gemini_web_search` tool in OpenCode that calls the local `gemini` CLI with Google Search grounding and returns an answer **only if** it includes:

- A `## Sources` Markdown section, **and**
- At least one inline `[Source](https://...)` citation outside any code or HTML block.

Responses that violate the contract throw, so the model cannot ship un-sourced claims.

The plugin also injects a system-prompt hint so the model knows when to use the tool (current events, version numbers, prices, weather, recency keywords like "latest", "최신", "오늘", etc.).

## Hardening (the contract)

Every invocation:

1. **Privacy override**: writes a per-invocation `settings.json` with `usageStatisticsEnabled: false` to a temp file (mode `0o600`) and points `GEMINI_CLI_SYSTEM_SETTINGS_PATH` at it. **Your `~/.gemini/settings.json` is never read or modified.** The temp file is removed in a `finally` block.
2. **No `--model` flag**: the user's gemini default model is always honored.
3. **Citation contract enforced**: see above.
4. **Terminal-control sanitisation**: all gemini stdout passes through a strict ECMA-48 sanitiser (CSI, OSC/DCS/SOS/PM/APC, Fe escapes, C0 controls except TAB/LF/CR) before being returned to OpenCode.
5. **Prompt-injection resistance**: the user query is `JSON.stringify`'d into the gemini prompt, so newlines and fake system markers in the user input cannot break out of the user-question scope.
6. **Resource limits**: query length, prompt byte size, stdout buffer, and wall-clock timeout are all bounded; over-limit calls are rejected before spawning.
7. **Process lifecycle**: `SIGTERM` → 250 ms grace → `SIGKILL` fallback; honors `AbortSignal` from OpenCode's tool context.

## Install

```bash
npm install -D @happycastle/opencode-gemini-search
```

You also need the [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed and authenticated (`gemini auth login`).

## Configure

In your project's `opencode.json` (or `~/.config/opencode/opencode.json`):

```json
{
  "plugin": ["@happycastle/opencode-gemini-search"]
}
```

That's it. The `gemini_web_search` tool is now available to your model.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEMINI_BINARY` | `gemini` | Path to the gemini CLI |
| `GEMINI_SEARCH_TIMEOUT` | `600000` | Wall-clock timeout per search (ms) |
| `GEMINI_SEARCH_MAX_BUFFER` | `52428800` | Max stdout/stderr bytes |
| `GEMINI_SEARCH_MAX_QUERY_CHARS` | `32768` | Max user query length (UTF-16 code units) |
| `GEMINI_SEARCH_MAX_PROMPT_BYTES` | `98304` | Max final prompt size (UTF-8 bytes) |
| `OPENCODE_GEMINI_SEARCH_DEBUG` | _(unset)_ | Set to `1` to log when recency keywords are detected in user messages |

## Usage

Once installed, just ask normally:

```
What's the latest Node.js LTS version?
오늘 비트코인 시세 알려줘
What did Apple announce at WWDC 2026?
```

The model will call `gemini_web_search` and return a sourced answer.

## Companion package

For Claude Code / claude.ai, see [`@happycastle/gemini-search`](https://www.npmjs.com/package/@happycastle/gemini-search) — same hardening contract, packaged as a Claude Code plugin.

## Contributing

```bash
npm install
npm run build
npm test
```

Conventional commits required. `semantic-release` cuts versions on push to `main`.

## License

MIT © happycastle

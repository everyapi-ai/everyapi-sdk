# everyapi-sdk

Shared Go SDK for the EveryAPI tool-chain. Provides the building blocks
that the CLI (`clients/cli`), the edge agent (`clients/edge`), and any
future EveryAPI surface (browser extension, mobile, …) consume in
common:

| Package | Purpose |
|---|---|
| `api/` | HTTP client for the EveryAPI gateway — device-auth, jump-session, seller OAuth (Claude / Gemini / Codex), token list / key fetch, relay-key resolver, TLS public-key pinning |
| `config/` | `~/.config/everyapi/credentials.json` read/write — atomic, mode 0600 |
| `oauthloopback/` | One-shot HTTP listener on a random loopback port for OAuth code redirects |
| `sanitizer/` | Local privacy-sanitizer proxy used by `everyapi proxy start` |

## Module path

`github.com/everyapi-ai/everyapi-sdk`

Consumed locally via the `clients/go.work` workspace at the repo root.
When published, the public mirror lives at
[`github.com/everyapi-ai/everyapi-sdk`](https://github.com/everyapi-ai/everyapi-sdk).

## Stability

API stability follows the EveryAPI tool-chain release cadence. The
packages here are extracted from the previously-private `internal/`
namespace of the CLI module (pre–`refactor/clients-monorepo`), so the
shape is already battle-tested in production. Breaking changes will
follow standard Go semver.

## History

Split out from `github.com/everyapi-ai/everyapi-ai` (the CLI module)
in the `refactor/clients-monorepo` split, when multiple surfaces
sharing one `internal/` namespace made re-exporting and independent
release impractical. See `docs/cli/` for the prior single-module
rationale.

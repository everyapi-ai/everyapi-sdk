# everyapi-sdk

Shared Go SDK for the EveryAPI tool-chain. Provides the building blocks
that the CLI (`clients/cli`), the edge agent (`clients/edge`), and any
future EveryAPI surface (browser extension, mobile, …) consume in
common:

| Package | Purpose |
|---|---|
| `api/` | HTTP client for the EveryAPI gateway — Agent Session queries and policy controls, device-auth, jump-session, seller OAuth (Claude / Gemini / Codex), token list / key fetch, relay-key resolver, TLS public-key pinning |
| `config/` | `~/.config/everyapi/credentials.json` read/write — atomic, mode 0600 |
| `oauthloopback/` | One-shot HTTP listener on a random loopback port for OAuth code redirects |
| `otelagentsession/` | Optional OpenTelemetry GenAI attribute adapter for canonical Session identity; content is disabled by default |
| `sanitizer/` | Local privacy-sanitizer proxy used by `everyapi proxy start` |

## Agent Session telemetry

The OpenTelemetry GenAI semantic conventions are still Development status, so
the SDK exposes a replaceable mapper instead of coupling persisted EveryAPI
models to one convention revision:

```go
mapper := otelagentsession.NewDevelopmentMapper()
span.SetAttributes(mapper.Attributes(otelagentsession.Context{
    Session: session,
    AgentID: hostedAgentID, // optional; never inferred from Session.ID
})...)
```

`Session.ID` maps to `gen_ai.conversation.id`. `gen_ai.agent.id` is emitted only
when the caller supplies a separate stable hosted-Agent resource ID. By default,
the mapper never emits instructions, messages, tool arguments/results, raw
aliases, prompts, or responses.

OpenTelemetry classifies instructions and input/output messages as sensitive
opt-in attributes. Enable them only when the telemetry destination has the
necessary privacy controls, retention policy, and payload limits:

```go
mapper := otelagentsession.NewDevelopmentMapperWithOptions(
    otelagentsession.WithContentAttributes(),
)
span.SetAttributes(mapper.Attributes(otelagentsession.Context{
    Session: session,
    Content: &otelagentsession.ContentAttributes{
        SystemInstructions: systemInstructionsJSON,
        InputMessages:      inputMessagesJSON,
        OutputMessages:     outputMessagesJSON,
    },
})...)
```

The three values are `json.RawMessage` arrays and must follow the corresponding
OpenTelemetry GenAI JSON schemas. The Development mapper rejects malformed
arrays and values that do not satisfy the current schemas' required structural
contract, including message roles, parts, and output finish reasons. Supplying
`Context.Content` without `WithContentAttributes()` remains content-free. Since
the convention is still Development, use the matching mapper version when the
upstream schemas change.

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

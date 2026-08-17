// Shared relay-key resolution used by the CLI. It maps (creds, group) → "sk-everyapi-…" key with the same precedence rules:
//
//   - default group + cached key on creds → cache hit, no API call
//   - default group + no cache → the enabled auto-group token when the account has one, else the newest enabled token; fetch + write back into creds + persist via config.Save (Save errors are surfaced as a wrapping error; caller decides whether to downgrade them)
//   - non-empty group → bypass cache on both read and write; pick newest enabled token whose Group matches. Caller-side caching is deliberately skipped so the default-group lookup doesn't get poisoned.
//
// Originally lived in clients/cli (`cmd/relaykey.go`); promoted here in R5 so behaviour drift between surfaces is impossible.
package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/everyapi-ai/everyapi-sdk/config"
)

// relayKeyRefreshSkew renews an OAuth2-issued relay key once it's within a day of expiry, so a still-valid key is swapped out before it can lapse.
const relayKeyRefreshSkew = 24 * time.Hour

// GroupAuto is the reserved token group that routes across every group the account can reach, instead of pinning traffic to one of them. Exported because the CLI creates keys in it and reads its grant, and a second literal that drifts from this one would silently un-do the resolution rule below.
const GroupAuto = "auto"

// ErrNoRelayKey: account has zero enabled relay API keys the caller can use. Callers map this to actionable UI ("create one in dashboard"). Distinct sentinel so a transport failure isn't confused with an empty-account verdict.
var ErrNoRelayKey = errors.New("no enabled relay API key on the account")

// ErrNoRelayKeyForGroup: group filter was set but no enabled token matches that group. Distinct from ErrNoRelayKey so callers can name the group in the hint.
var ErrNoRelayKeyForGroup = errors.New("no enabled relay API key in the requested group")

// ErrCacheSave wraps the underlying config.Save error when the resolver couldn't persist the cache write. The KEY is still returned alongside this error so the caller can complete the in-flight action; downgrading to a warning / notification is the caller's responsibility.
type ErrCacheSave struct{ Err error }

func (e *ErrCacheSave) Error() string {
	return "cache relay key: " + e.Err.Error()
}
func (e *ErrCacheSave) Unwrap() error { return e.Err }

// ResolveRelayKey is the shared resolver. See package doc for the precedence rules. Mutates *creds.RelayKey only on the default- group success path. Persists via config.Save in that same path; a Save failure returns the resolved key paired with *ErrCacheSave so the caller can decide whether to abort or warn-and-proceed.
func ResolveRelayKey(ctx context.Context, creds *config.Credentials, group string) (key string, err error) {
	if creds == nil {
		return "", errors.New("not signed in")
	}
	// Set only on the one-shot re-resolution of a pre-tiering cache (see below). It makes that re-resolution strictly optional: the deferred handler swaps any hard failure back to the cached key, so an offline launch, an unreachable gateway or a revoked management token degrades to exactly the behaviour that shipped before the tiering rather than turning a working install into an error. ErrCacheSave is left alone — it arrives WITH a usable key.
	var unstampedCache string
	defer func() {
		if err != nil && key == "" && unstampedCache != "" {
			key, err = unstampedCache, nil
		}
	}()
	if group == "" && creds.RelayKey != "" {
		if key, ok, saveErr := refreshRelayKeyIfNeeded(ctx, creds); ok {
			// An OAuth2-issued key is minted for this login, not chosen from the account's token list, so the tiering below never applied to it and there is nothing to re-check.
			if saveErr != nil {
				// Key rotated but couldn't be persisted — return the fresh key paired with *ErrCacheSave so the caller completes the action and can warn instead of silently losing the rotated key.
				return key, &ErrCacheSave{Err: saveErr}
			}
			return key, nil
		}
		// A cache written before the system-managed tiering existed may hold exactly the key that tiering demotes — see Credentials.RelayKeySystemChecked. Falling through re-resolves once and stamps the flag; every launch after that is a cache hit again.
		//
		// OAuth logins are exempt whatever the flag says: their key is minted for the login rather than chosen from the account's token list, so the tiering never applied to it. refreshRelayKeyIfNeeded returns ok=false both when no refresh is due and when one failed, so the OAuth check has to be made here rather than inferred from that call.
		if creds.RelayKeySystemChecked || creds.OAuthClientID != "" {
			return creds.RelayKey, nil
		}
		unstampedCache = creds.RelayKey
	}

	// Region-aware: relay-key lookup is a command dial path, so it honors settings.gateway_region (via ForCredentials) rather than the raw login base. Otherwise `use --group` / `status` for a user who switched region without re-login would hit the unreachable login gateway here — before the region-resolved probe/relay calls downstream ever run.
	client := ForCredentials(creds)
	tokens, err := client.ListEnabledTokens(ctx)
	if err != nil {
		return "", fmt.Errorf("look up relay API key: %w", err)
	}
	// Default group: prefer the auto-group token. It is the only key that routes across every group the account can reach, so it is what a launch with no explicit --group should ride. Taking the list head instead handed the default to whatever token was created last — a key scoped to one group, whose /v1/models is a subset of the account's models, silently narrowing every client launched after it. Any other enabled token remains the fallback for accounts without an auto key; the resolver never creates one on this path. The default arm scans the whole list rather than stopping at the auto token: knowing whether ANY other enabled key exists is what makes the grant check below decidable, and an early break left that unknown.
	//
	// System-managed keys are held back in a third tier. They belong to an EveryAPI client rather than the user and are deliberately model-limited, so treating one as a normal candidate collapses every launched client's catalogue to that key's subset — the failure that motivated this tier: an account holding both its own auto key and the Connect app's shared diagnostics key (also auto-group) had launches routed through the diagnostics key, cutting a 23-model catalogue to 3 and 403-ing on the model Claude Code boots with. They stay eligible as a LAST resort: an account whose only enabled key is a system one must keep working, and "fewer models" beats ErrNoRelayKey.
	var pick, autoPick, fallback *TokenSummary
	// Held by value, not pointer: this one is consulted AFTER the auto-create branch below reassigns `tokens`, which would strand a pointer on the old backing array.
	var systemFallback TokenSummary
	haveSystemFallback := false
	rememberSystem := func(t TokenSummary) {
		if !haveSystemFallback {
			systemFallback, haveSystemFallback = t, true
		}
	}
	for i := range tokens {
		if tokens[i].Status != TokenStatusEnabled {
			continue
		}
		if group != "" {
			if tokens[i].Group != group {
				continue
			}
			if tokens[i].SystemManaged {
				rememberSystem(tokens[i])
				continue
			}
			pick = &tokens[i]
			break
		}
		if tokens[i].SystemManaged {
			rememberSystem(tokens[i])
			continue
		}
		if tokens[i].Group == GroupAuto {
			if autoPick == nil {
				autoPick = &tokens[i]
			}
			continue
		}
		if fallback == nil {
			fallback = &tokens[i]
		}
	}
	if group == "" {
		pick = autoPick
		// Where to go when the auto key turns out to be unusable: an ordinary key first, the EveryAPI-owned one only when the account has nothing else. Demoting system keys must not disable this downgrade — an account whose sole other enabled key is system-managed would otherwise keep a known-dead auto key and die on a zero-model catalogue, where before this tier existed it fell back and kept working. Safe to hold as a pointer into systemFallback: this arm only runs for group == "", which never reaches the auto-create branch that reassigns `tokens`.
		downgrade := fallback
		if downgrade == nil && haveSystemFallback {
			downgrade = &systemFallback
		}
		switch {
		case pick == nil:
			pick = downgrade
		case downgrade != nil:
			// Prefer the auto key only while the account may still USE that group. A tier that loses the grant keeps its enabled auto token, and TokenAuth exempts "auto" from the group gate — so the key authenticates, then expands to an empty pool list and every launch dies on a zero-model catalogue. Costs one request, and only when there is another key worth falling back to. An unanswerable probe keeps the auto key: this check exists to dodge a known-bad pick, not to invent a downgrade.
			if usable, probeErr := client.autoGroupUsable(ctx); probeErr == nil && !usable {
				pick = downgrade
			}
		}
	}
	// autoPick/fallback are only assigned on the group == "" arm above, and are deliberately not consulted past this point: the auto-create branch below reassigns `tokens`, which would leave either pointer aimed at a stale backing array. systemFallback is exempt because it was copied by value for exactly this reason.
	if pick == nil && group == GroupAuto {
		createErr := client.CreateToken(ctx, TokenCreate{
			Name:            "Auto",
			ExpiredTime:     TokenExpiresNever,
			UnlimitedQuota:  true,
			Group:           GroupAuto,
			CrossGroupRetry: true,
		})
		if createErr != nil {
			createErr = fmt.Errorf("create auto relay API key: %w", createErr)
		} else if refreshed, listErr := client.ListEnabledTokens(ctx); listErr != nil {
			createErr = fmt.Errorf("look up created auto relay API key: %w", listErr)
		} else {
			tokens = refreshed
			for i := range tokens {
				// Skip system keys here too: the account may already hold an EveryAPI-owned auto key, and matching it would hand back the narrow key we just created a replacement for.
				if tokens[i].Status == TokenStatusEnabled && tokens[i].Group == GroupAuto && !tokens[i].SystemManaged {
					pick = &tokens[i]
					break
				}
			}
		}
		// Only fatal when there is nothing to fall back to. An account holding an EveryAPI-owned auto key used to launch fine on it; now that such a key no longer satisfies the search, a failed create (token ceiling reached, network blip) would turn a working setup into a hard error. Prefer the narrower key — that is exactly the behaviour that shipped before this field existed.
		if pick == nil && createErr != nil && !haveSystemFallback {
			return "", createErr
		}
	}
	// Last resort, deliberately after the auto-create attempt: an account whose only enabled key is EveryAPI-owned is better served by a fresh key of its own than by the client-shared one. If no such key could be made, fall back rather than fail — that key's narrower model set still beats refusing to launch, and this is exactly the shape a user who only ever installed a client, never running the CLI, arrives in.
	if pick == nil && haveSystemFallback {
		pick = &systemFallback
	}
	if pick == nil {
		if group != "" {
			return "", ErrNoRelayKeyForGroup
		}
		return "", ErrNoRelayKey
	}
	key, err = client.TokenKey(ctx, pick.ID)
	if err != nil {
		return "", fmt.Errorf("fetch relay API key %q: %w", pick.Name, err)
	}

	if group != "" {
		// Deliberate per-run override — never cache; the default path must keep resolving the default-group key.
		return key, nil
	}

	creds.RelayKey = key
	creds.RelayKeyTokenID = pick.ID
	// This key came out of the tiering above, so the cache no longer needs re-resolving on the next launch.
	creds.RelayKeySystemChecked = true
	if saveErr := config.Save(creds); saveErr != nil {
		return key, &ErrCacheSave{Err: saveErr}
	}
	return key, nil
}

// RefreshOAuthRelayKey unconditionally rotates an OAuth2-issued relay key. Use this only after the current access token was rejected by the gateway. Unlike proactive refresh, a refresh failure is returned and the rejected key is never handed back to the caller.
func RefreshOAuthRelayKey(ctx context.Context, creds *config.Credentials) (string, error) {
	if creds == nil {
		return "", errors.New("not signed in")
	}
	if creds.RefreshToken == "" || creds.OAuthClientID == "" {
		return "", errors.New("OAuth2 refresh material is unavailable")
	}
	tok, err := New(config.ResolveAPIBaseForBase(creds.APIBase), "").OAuth2Refresh(ctx, creds.OAuthClientID, creds.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("refresh OAuth2 relay key: %w", err)
	}
	creds.RelayKey = tok.AccessToken
	creds.AccessToken = tok.AccessToken
	creds.RefreshToken = tok.RefreshToken
	creds.RelayKeyExpiresAt = tok.ExpiresAt
	if saveErr := config.Save(creds); saveErr != nil {
		return tok.AccessToken, &ErrCacheSave{Err: saveErr}
	}
	return tok.AccessToken, nil
}

// InvalidateCachedRelayKey clears the cached default-group relay key (creds.RelayKey) and persists, so the next default-group ResolveRelayKey re-resolves from scratch — the account's auto key, or its newest enabled token when there is none — instead of re-handing-out a key the gateway just rejected. Call it when a relay request authenticated with the cached key comes back definitively 401/unauthorized (the token was disabled, revoked, expired, or ran out of quota server-side) — the default-group cache otherwise has no way to learn its key died and keeps returning it on every run.
//
// No-op when nothing is cached. The in-memory creds.RelayKey is cleared before the persist attempt, so even if Save fails the current process won't reuse the dead key; the returned Save error lets the caller warn that the on-disk cache couldn't be cleared.
//
// Only invalidate when the rejected key WAS the default-group cache — a group-scoped key is resolved fresh and never cached, so its rejection must not wipe an unrelated (possibly still-valid) default cache. That gating is the caller's responsibility.
func InvalidateCachedRelayKey(creds *config.Credentials) error {
	if creds == nil || creds.RelayKey == "" {
		return nil
	}
	// OAuth2 mode: the cached relay key IS the OAuth access token (see refreshRelayKeyIfNeeded keeping RelayKey == AccessToken in sync), and a 401 there means "the access token needs refreshing", not "the cache is poisoned". Clearing it would strand the next run — with RelayKey empty, ResolveRelayKey skips the OAuth refresh branch and falls to a management ListTokens call that, for an OAuth2 login (UserID often 0), 401s and forces a full browser re-login even after the user fixes the cause (e.g. tops up quota). Leave it for the next-run refresh to rotate.
	if creds.RefreshToken != "" && creds.OAuthClientID != "" {
		return nil
	}
	creds.RelayKey = ""
	creds.RelayKeyTokenID = 0
	return config.Save(creds)
}

// SelectRelayKey makes one enabled token the persisted default relay key. Callers are responsible for presenting only enabled tokens; the backend is still authoritative and rejects an unusable key when it is relayed.
func SelectRelayKey(ctx context.Context, creds *config.Credentials, tokenID int) error {
	if creds == nil {
		return errors.New("not signed in")
	}
	if tokenID <= 0 {
		return errors.New("invalid relay API key id")
	}
	key, err := ForCredentials(creds).TokenKey(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("fetch selected relay API key: %w", err)
	}
	creds.RelayKey = key
	creds.RelayKeyTokenID = tokenID
	// An explicit choice needs no re-resolution: the user named this key, and re-running the tiering on the next launch would only discard what they picked.
	creds.RelayKeySystemChecked = true
	// A manual account-token selection leaves OAuth key rotation mode. Keeping old refresh material would silently replace the chosen key later.
	creds.RefreshToken = ""
	creds.RelayKeyExpiresAt = 0
	creds.OAuthClientID = ""
	return config.Save(creds)
}

// SelectAutoRelayKey selects an enabled group=auto token, creating the canonical unlimited token when the account does not have one yet. The bool reports whether this call created the token.
func SelectAutoRelayKey(ctx context.Context, creds *config.Credentials) (bool, error) {
	if creds == nil {
		return false, errors.New("not signed in")
	}
	client := ForCredentials(creds)
	tokens, err := client.ListEnabledTokens(ctx)
	if err != nil {
		return false, fmt.Errorf("look up auto relay API key: %w", err)
	}
	// Status is re-checked here even though ListEnabledTokens asks the gateway to filter: that filter is a query parameter an older gateway may ignore (see the pagination note on listTokens), and selecting a DISABLED auto token would persist a key that 401s on the very next launch. Matches the check ResolveRelayKey applies to the same list.
	//
	// System-managed keys are skipped for the same reason ResolveRelayKey demotes them, and it matters MORE here: this path PERSISTS its choice into creds.RelayKey, and the default-group arm of ResolveRelayKey returns that cache before it ever lists tokens. Matching an EveryAPI-owned auto key here would pin the account to that key's narrow model set on every subsequent launch, out of reach of the resolver's own tiering. The create below then gives the account an auto key of its own, which is exactly what it lacks.
	for _, token := range tokens {
		if token.Status == TokenStatusEnabled && token.Group == GroupAuto && !token.SystemManaged {
			return false, SelectRelayKey(ctx, creds, token.ID)
		}
	}
	if err := client.CreateToken(ctx, TokenCreate{
		Name:            "Auto",
		ExpiredTime:     TokenExpiresNever,
		UnlimitedQuota:  true,
		Group:           GroupAuto,
		CrossGroupRetry: true,
	}); err != nil {
		return false, fmt.Errorf("create auto relay API key: %w", err)
	}
	tokens, err = client.ListEnabledTokens(ctx)
	if err != nil {
		return true, fmt.Errorf("look up created auto relay API key: %w", err)
	}
	for _, token := range tokens {
		if token.Status == TokenStatusEnabled && token.Group == GroupAuto && !token.SystemManaged {
			return true, SelectRelayKey(ctx, creds, token.ID)
		}
	}
	return true, errors.New("created auto relay API key was not returned by the server")
}

// refreshRelayKeyIfNeeded proactively renews an OAuth2-issued relay key that's within relayKeyRefreshSkew of expiry, updating + persisting creds in place. Returns (newKey, true) only on a successful refresh; (—, false) when there's nothing to renew (legacy/manual creds with no refresh material) or the refresh failed — the caller then uses the cached key, which is either still valid or prompts a re-login on the next API rejection.
func refreshRelayKeyIfNeeded(ctx context.Context, creds *config.Credentials) (string, bool, error) {
	if creds.RefreshToken == "" || creds.OAuthClientID == "" || creds.RelayKeyExpiresAt == 0 {
		return "", false, nil
	}
	if time.Until(time.Unix(creds.RelayKeyExpiresAt, 0)) > relayKeyRefreshSkew {
		return "", false, nil
	}
	key, err := RefreshOAuthRelayKey(ctx, creds)
	if err != nil {
		var cacheErr *ErrCacheSave
		if key != "" && errors.As(err, &cacheErr) {
			return key, true, cacheErr.Err
		}
		return "", false, nil
	}
	return key, true, nil
}

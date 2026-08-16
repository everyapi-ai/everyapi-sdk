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
func ResolveRelayKey(ctx context.Context, creds *config.Credentials, group string) (string, error) {
	if creds == nil {
		return "", errors.New("not signed in")
	}
	if group == "" && creds.RelayKey != "" {
		if key, ok, saveErr := refreshRelayKeyIfNeeded(ctx, creds); ok {
			if saveErr != nil {
				// Key rotated but couldn't be persisted — return the fresh key paired with *ErrCacheSave so the caller completes the action and can warn instead of silently losing the rotated key.
				return key, &ErrCacheSave{Err: saveErr}
			}
			return key, nil
		}
		return creds.RelayKey, nil
	}

	// Region-aware: relay-key lookup is a command dial path, so it honors settings.gateway_region (via ForCredentials) rather than the raw login base. Otherwise `use --group` / `status` for a user who switched region without re-login would hit the unreachable login gateway here — before the region-resolved probe/relay calls downstream ever run.
	client := ForCredentials(creds)
	tokens, err := client.ListEnabledTokens(ctx)
	if err != nil {
		return "", fmt.Errorf("look up relay API key: %w", err)
	}
	// Default group: prefer the auto-group token. It is the only key that routes across every group the account can reach, so it is what a launch with no explicit --group should ride. Taking the list head instead handed the default to whatever token was created last — a key scoped to one group, whose /v1/models is a subset of the account's models, silently narrowing every client launched after it. Any other enabled token remains the fallback for accounts without an auto key; the resolver never creates one on this path. The default arm scans the whole list rather than stopping at the auto token: knowing whether ANY other enabled key exists is what makes the grant check below decidable, and an early break left that unknown.
	var pick, autoPick, fallback *TokenSummary
	for i := range tokens {
		if tokens[i].Status != TokenStatusEnabled {
			continue
		}
		if group != "" {
			if tokens[i].Group != group {
				continue
			}
			pick = &tokens[i]
			break
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
		switch {
		case pick == nil:
			pick = fallback
		case fallback != nil:
			// Prefer the auto key only while the account may still USE that group. A tier that loses the grant keeps its enabled auto token, and TokenAuth exempts "auto" from the group gate — so the key authenticates, then expands to an empty pool list and every launch dies on a zero-model catalogue. Costs one request, and only when there is another key worth falling back to. An unanswerable probe keeps the auto key: this check exists to dodge a known-bad pick, not to invent a downgrade.
			if usable, probeErr := client.autoGroupUsable(ctx); probeErr == nil && !usable {
				pick = fallback
			}
		}
	}
	// autoPick/fallback are only assigned on the group == "" arm above, and are deliberately not consulted past this point: the auto-create branch below reassigns `tokens`, which would leave either pointer aimed at a stale backing array.
	if pick == nil && group == GroupAuto {
		if err := client.CreateToken(ctx, TokenCreate{
			Name:            "Auto",
			ExpiredTime:     TokenExpiresNever,
			UnlimitedQuota:  true,
			Group:           GroupAuto,
			CrossGroupRetry: true,
		}); err != nil {
			return "", fmt.Errorf("create auto relay API key: %w", err)
		}
		tokens, err = client.ListEnabledTokens(ctx)
		if err != nil {
			return "", fmt.Errorf("look up created auto relay API key: %w", err)
		}
		for i := range tokens {
			if tokens[i].Status == TokenStatusEnabled && tokens[i].Group == GroupAuto {
				pick = &tokens[i]
				break
			}
		}
	}
	if pick == nil {
		if group != "" {
			return "", ErrNoRelayKeyForGroup
		}
		return "", ErrNoRelayKey
	}
	key, err := client.TokenKey(ctx, pick.ID)
	if err != nil {
		return "", fmt.Errorf("fetch relay API key %q: %w", pick.Name, err)
	}

	if group != "" {
		// Deliberate per-run override — never cache; the default path must keep resolving the default-group key.
		return key, nil
	}

	creds.RelayKey = key
	creds.RelayKeyTokenID = pick.ID
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
	for _, token := range tokens {
		if token.Status == TokenStatusEnabled && token.Group == GroupAuto {
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
		if token.Status == TokenStatusEnabled && token.Group == GroupAuto {
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

// Shared relay-key resolution used by the CLI.
// It maps (creds, group) → "sk-everyapi-…" key
// with the same precedence rules:
//
//   - default group + cached key on creds → cache hit, no API call
//   - default group + no cache → newest enabled token, fetch +
//     write back into creds + persist via config.Save (Save errors
//     are surfaced as a wrapping error; caller decides whether to
//     downgrade them)
//   - non-empty group → bypass cache on both read and write; pick
//     newest enabled token whose Group matches. Caller-side caching
//     is deliberately skipped so the default-group lookup doesn't
//     get poisoned.
//
// Originally lived in clients/cli (`cmd/relaykey.go`); promoted
// here in R5 so behaviour drift between surfaces is impossible.
package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/everyapi-ai/everyapi-sdk/config"
)

// relayKeyRefreshSkew renews an OAuth2-issued relay key once it's within a day
// of expiry, so a still-valid key is swapped out before it can lapse.
const relayKeyRefreshSkew = 24 * time.Hour

// ErrNoRelayKey: account has zero enabled relay API keys the caller
// can use. Callers map this to actionable UI ("create one in
// dashboard"). Distinct sentinel so a transport failure isn't
// confused with an empty-account verdict.
var ErrNoRelayKey = errors.New("no enabled relay API key on the account")

// ErrNoRelayKeyForGroup: group filter was set but no enabled token
// matches that group. Distinct from ErrNoRelayKey so callers can
// name the group in the hint.
var ErrNoRelayKeyForGroup = errors.New("no enabled relay API key in the requested group")

// ErrCacheSave wraps the underlying config.Save error when the
// resolver couldn't persist the cache write. The KEY is still
// returned alongside this error so the caller can complete the
// in-flight action; downgrading to a warning / notification is the
// caller's responsibility.
type ErrCacheSave struct{ Err error }

func (e *ErrCacheSave) Error() string {
	return "cache relay key: " + e.Err.Error()
}
func (e *ErrCacheSave) Unwrap() error { return e.Err }

// ResolveRelayKey is the shared resolver. See package doc for the
// precedence rules. Mutates *creds.RelayKey only on the default-
// group success path. Persists via config.Save in that same path;
// a Save failure returns the resolved key paired with *ErrCacheSave
// so the caller can decide whether to abort or warn-and-proceed.
func ResolveRelayKey(ctx context.Context, creds *config.Credentials, group string) (string, error) {
	if creds == nil {
		return "", errors.New("not signed in")
	}
	if group == "" && creds.RelayKey != "" {
		if key, ok, saveErr := refreshRelayKeyIfNeeded(ctx, creds); ok {
			if saveErr != nil {
				// Key rotated but couldn't be persisted — return the fresh key
				// paired with *ErrCacheSave so the caller completes the action
				// and can warn instead of silently losing the rotated key.
				return key, &ErrCacheSave{Err: saveErr}
			}
			return key, nil
		}
		return creds.RelayKey, nil
	}

	client := New(creds.APIBase, creds.AccessToken).WithUserID(creds.UserID)
	tokens, err := client.ListTokens(ctx)
	if err != nil {
		return "", fmt.Errorf("look up relay API key: %w", err)
	}
	var pick *TokenSummary
	for i := range tokens {
		if tokens[i].Status != TokenStatusEnabled {
			continue
		}
		if group != "" && tokens[i].Group != group {
			continue
		}
		pick = &tokens[i]
		break
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
		// Deliberate per-run override — never cache; the default
		// path must keep resolving the default-group key.
		return key, nil
	}

	creds.RelayKey = key
	if saveErr := config.Save(creds); saveErr != nil {
		return key, &ErrCacheSave{Err: saveErr}
	}
	return key, nil
}

// refreshRelayKeyIfNeeded proactively renews an OAuth2-issued relay key that's
// within relayKeyRefreshSkew of expiry, updating + persisting creds in place.
// Returns (newKey, true) only on a successful refresh; (—, false) when there's
// nothing to renew (legacy/manual creds with no refresh material) or the
// refresh failed — the caller then uses the cached key, which is either still
// valid or prompts a re-login on the next API rejection.
func refreshRelayKeyIfNeeded(ctx context.Context, creds *config.Credentials) (string, bool, error) {
	if creds.RefreshToken == "" || creds.OAuthClientID == "" || creds.RelayKeyExpiresAt == 0 {
		return "", false, nil
	}
	if time.Until(time.Unix(creds.RelayKeyExpiresAt, 0)) > relayKeyRefreshSkew {
		return "", false, nil
	}
	tok, err := New(creds.APIBase, "").OAuth2Refresh(ctx, creds.OAuthClientID, creds.RefreshToken)
	if err != nil {
		return "", false, nil
	}
	// In OAuth2 mode the relay key is also the stored access token; keep both in
	// sync so management-less commands that read AccessToken see the fresh key.
	creds.RelayKey = tok.AccessToken
	creds.AccessToken = tok.AccessToken
	creds.RefreshToken = tok.RefreshToken
	creds.RelayKeyExpiresAt = tok.ExpiresAt
	// Surface a persist failure instead of swallowing it: the key just
	// rotated, so a dropped Save means a re-refresh next run (or use of a
	// stale cached key). The caller pairs this with *ErrCacheSave.
	saveErr := config.Save(creds)
	return tok.AccessToken, true, saveErr
}

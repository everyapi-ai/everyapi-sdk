package api

import "github.com/everyapi-ai/everyapi-sdk/config"

// ForCredentials builds a management-API client for the logged-in account,
// authenticated with the stored access token.
//
// It dials the region-selected gateway: config.ResolveAPIBase applies
// settings.gateway_region at call time, so `everyapi settings set
// gateway_region cn/global` takes effect on every command without a
// re-login. creds.APIBase is deliberately NOT used as the dial base and
// stays the login value — login is its only author, so the RelayKey cache
// that use/status write back to credentials.json never rewrites the stored
// api_base. A self-hosted --api-base still wins: ResolveAPIBase returns a
// non-official creds base unchanged.
//
// Use this for every access-token-authenticated command client. Relay
// clients are keyed by a relay key (not the access token), so they build the
// base directly with config.ResolveAPIBaseForBase(creds.APIBase) — the same
// region resolution this helper applies — instead of going through it.
func ForCredentials(creds *config.Credentials) *Client {
	return New(config.ResolveAPIBaseForBase(creds.APIBase), creds.AccessToken).WithUserID(creds.UserID)
}

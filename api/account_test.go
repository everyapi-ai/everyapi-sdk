package api

import (
	"testing"

	"github.com/everyapi-ai/everyapi-sdk/config"
)

// ForCredentials must dial the region-selected gateway (settings.gateway_region
// resolved via config.ResolveAPIBase), NOT the raw creds.APIBase field — that
// is the whole point of the helper. This guards against a regression back to
// api.New(creds.APIBase, ...), which silenced `settings set gateway_region`
// for every command until a re-login rewrote credentials.json.
func TestForCredentialsAppliesGatewayRegion(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// Logged in against the official global gateway on disk...
	if err := config.Save(&config.Credentials{
		APIBase:     config.DefaultAPIBase,
		AccessToken: "tok",
		UserID:      2,
	}); err != nil {
		t.Fatalf("Save credentials: %v", err)
	}
	// ...but the user later switched region to cn WITHOUT re-logging-in.
	if err := config.SaveSettings(&config.Settings{GatewayRegion: "cn"}); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	c := ForCredentials(&config.Credentials{APIBase: config.DefaultAPIBase, AccessToken: "tok", UserID: 2})
	if c.base != config.ChinaAPIBase {
		t.Fatalf("ForCredentials dialed %q, want region-resolved %q "+
			"(regression: reading creds.APIBase instead of ResolveAPIBase)", c.base, config.ChinaAPIBase)
	}
	if c.token != "tok" || c.userID != 2 {
		t.Fatalf("ForCredentials lost account identity: token=%q userID=%d", c.token, c.userID)
	}
}

// A self-hosted gateway (a non-official base on disk) must NOT be overridden by
// gateway_region: ResolveAPIBase returns a custom creds base unchanged, so
// pinning the CLI at a private backend keeps working regardless of the region
// preference.
func TestForCredentialsKeepsSelfHostBase(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	const selfHost = "http://localhost:8787"
	if err := config.Save(&config.Credentials{
		APIBase:     selfHost,
		AccessToken: "tok",
		UserID:      2,
	}); err != nil {
		t.Fatalf("Save credentials: %v", err)
	}
	if err := config.SaveSettings(&config.Settings{GatewayRegion: "cn"}); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	c := ForCredentials(&config.Credentials{APIBase: selfHost, AccessToken: "tok", UserID: 2})
	if c.base != selfHost {
		t.Fatalf("ForCredentials overrode self-host base with region: got %q, want %q", c.base, selfHost)
	}
}

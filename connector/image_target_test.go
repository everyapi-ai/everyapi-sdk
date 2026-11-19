package connector

import (
	"net/http"
	"testing"
)

// Codex's built-in image tool posts to the Images API on the provider's base URL. In transparent mode that is api.openai.com, so both routes must relay to EveryAPI; anything else under /v1/images stays fail-closed rather than reaching OpenAI with the placeholder credential.
func TestOpenAITargetRelaysTheImageRoutes(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/images/generations", "/v1/images/edits"} {
		if got := registry.Decide("api.openai.com", http.MethodPost, path).Action; got != ActionRelay {
			t.Errorf("POST %s action = %q, want %q", path, got, ActionRelay)
		}
	}
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/images/generations"},
		{method: http.MethodPost, path: "/v1/images/variations"},
		{method: http.MethodPost, path: "/v1/images/generations/extra"},
	} {
		if got := registry.Decide("api.openai.com", test.method, test.path).Action; got != ActionBlock {
			t.Errorf("%s %s action = %q, want fail-closed %q", test.method, test.path, got, ActionBlock)
		}
	}
}

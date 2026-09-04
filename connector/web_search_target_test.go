package connector

import (
	"net/http"
	"testing"
)

func TestOpenAITargetRelaysOnlyTheStandaloneSearchRoute(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}

	if got := registry.Decide("api.openai.com", http.MethodPost, "/v1/alpha/search").Action; got != ActionRelay {
		t.Fatalf("POST /v1/alpha/search action = %q, want %q", got, ActionRelay)
	}
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/alpha/search"},
		{method: http.MethodPost, path: "/v1/alpha/search/future"},
		{method: http.MethodPost, path: "/v1/alpha/other"},
	} {
		if got := registry.Decide("api.openai.com", test.method, test.path).Action; got != ActionBlock {
			t.Errorf("%s %s action = %q, want fail-closed %q", test.method, test.path, got, ActionBlock)
		}
	}
}

package connector

import (
	"net/http"
	"testing"
)

func TestDefaultRegistryDecidesModelTrafficByOfficialOrigin(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	tests := []struct {
		name   string
		host   string
		method string
		path   string
		want   Action
	}{
		{name: "anthropic messages", host: "api.anthropic.com", method: http.MethodPost, path: "/v1/messages", want: ActionRelay},
		{name: "anthropic token count", host: "api.anthropic.com", method: http.MethodPost, path: "/v1/messages/count_tokens", want: ActionRelay},
		{name: "openai responses", host: "api.openai.com", method: http.MethodPost, path: "/v1/responses", want: ActionRelay},
		{name: "openai responses compact", host: "api.openai.com", method: http.MethodPost, path: "/v1/responses/compact", want: ActionRelay},
		{name: "gemini generate", host: "generativelanguage.googleapis.com", method: http.MethodPost, path: "/v1beta/models/gemini-2.5-pro:generateContent", want: ActionRelay},
		{name: "gemini stream", host: "generativelanguage.googleapis.com", method: http.MethodPost, path: "/v1beta/models/gemini-2.5-pro:streamGenerateContent", want: ActionRelay},
		{name: "official non-model endpoint", host: "api.anthropic.com", method: http.MethodGet, path: "/api/oauth/profile", want: ActionDirect},
		{name: "unknown sensitive endpoint", host: "api.openai.com", method: http.MethodPost, path: "/v1/future-model-api", want: ActionBlock},
		{name: "unregistered host", host: "example.com", method: http.MethodPost, path: "/v1/responses", want: ActionDirect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := registry.Decide(tt.host, tt.method, tt.path).Action; got != tt.want {
				t.Fatalf("Decide(%q, %q, %q) action = %q, want %q", tt.host, tt.method, tt.path, got, tt.want)
			}
		})
	}
}

func TestRegistryRejectsDuplicateHosts(t *testing.T) {
	t.Parallel()

	_, err := NewRegistry([]Target{
		{Name: "one", Hosts: []string{"api.example.com"}},
		{Name: "two", Hosts: []string{"API.EXAMPLE.COM"}},
	})
	if err == nil {
		t.Fatal("NewRegistry accepted duplicate hosts")
	}
}

func TestRegistryRejectsAmbiguousOrUnsafeRoutes(t *testing.T) {
	t.Parallel()

	cases := []Target{
		{Name: "ambiguous", Hosts: []string{"api.example.com"}, Routes: []Route{{Exact: "/v1/a", Prefix: "/v1/", Action: ActionRelay}}},
		{Name: "missing-path", Hosts: []string{"api.example.com"}, Routes: []Route{{Action: ActionRelay}}},
		{Name: "missing-action", Hosts: []string{"api.example.com"}, Routes: []Route{{Exact: "/v1/a"}}},
		{Name: "bad-action", Hosts: []string{"api.example.com"}, Routes: []Route{{Exact: "/v1/a", Action: Action("fallback")}}},
	}
	for _, target := range cases {
		target := target
		t.Run(target.Name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRegistry([]Target{target}); err == nil {
				t.Fatal("NewRegistry unexpectedly accepted unsafe route")
			}
		})
	}
}

func TestDefaultRegistryDoesNotRelayFutureAnthropicSubpaths(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}

	decision := registry.Decide("api.anthropic.com", http.MethodPost, "/v1/messages/future")
	if decision.Action != ActionBlock {
		t.Fatalf("decision = %q, want %q", decision.Action, ActionBlock)
	}
}

func TestRegistryCopiesTargetDefinitions(t *testing.T) {
	t.Parallel()

	targets := []Target{{
		Name:              "test",
		Hosts:             []string{"api.example.com"},
		Routes:            []Route{{Method: http.MethodPost, Exact: "/v1/model", Action: ActionRelay}},
		SensitivePrefixes: []string{"/v1/"},
	}}
	registry, err := NewRegistry(targets)
	if err != nil {
		t.Fatal(err)
	}
	targets[0].Routes[0].Action = ActionDirect
	targets[0].SensitivePrefixes[0] = "/other/"

	if got := registry.Decide("api.example.com", http.MethodPost, "/v1/model").Action; got != ActionRelay {
		t.Fatalf("registry changed after caller mutation: %q", got)
	}
}

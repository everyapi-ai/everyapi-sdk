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

// TestGeminiTargetRelaysEveryActionTheGatewayServes pins the connector's gemini
// allowlist against what the gateway can actually serve. The allowlist is
// fail-closed via SensitivePrefixes "/v1beta/models/", so any model action
// missing from Routes is 403'd — harmless while transparent mode was opt-in,
// a user-visible regression once it became the default, because the injected
// path has no route filter and relays these fine.
func TestGeminiTargetRelaysEveryActionTheGatewayServes(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	const host = "generativelanguage.googleapis.com"

	// Actions the gateway's Gemini adaptor emits (see the backend's
	// channel/gemini adaptor: embedding models map to :embedContent /
	// :batchEmbedContents, everything else to :generateContent /
	// :streamGenerateContent). All must relay, not block.
	for _, action := range []string{
		":generateContent",
		":streamGenerateContent",
		":embedContent",
		":batchEmbedContents",
	} {
		path := "/v1beta/models/gemini-2.5-pro" + action
		if got := registry.Decide(host, http.MethodPost, path).Action; got != ActionRelay {
			t.Errorf("POST %s -> %v, want ActionRelay (the gateway serves this action)", path, got)
		}
	}

	// :countTokens stays blocked ON PURPOSE: the gateway rebuilds the upstream
	// URL from the model name and never emits it, so relaying would have a
	// token-count request answered as :generateContent. Blocking is the honest
	// failure until the gateway serves it. This asserts the choice is
	// deliberate rather than another gap.
	countTokens := "/v1beta/models/gemini-2.5-pro:countTokens"
	if got := registry.Decide(host, http.MethodPost, countTokens).Action; got != ActionBlock {
		t.Errorf("POST %s -> %v, want ActionBlock until the gateway can serve it", countTokens, got)
	}

	// An unknown future action must still fail closed — that is the point of
	// the allowlist.
	unknown := "/v1beta/models/gemini-2.5-pro:someFutureAction"
	if got := registry.Decide(host, http.MethodPost, unknown).Action; got != ActionBlock {
		t.Errorf("POST %s -> %v, want ActionBlock (allowlist must fail closed)", unknown, got)
	}
}

// TestRegistryFailsClosedOnNonCanonicalPath pins the dot-segment escape and the
// pass-through it must not break. Asserting merely "not ActionRelay" would make
// most of this vacuous — ActionDirect and ActionBlock are both "not relay" but
// mean opposite things here, and an earlier version of this fix blocked the
// direct cases by mistake. Each input gets an exact expected action.
func TestRegistryFailsClosedOnNonCanonicalPath(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, path string
		want       Action
		why        string
	}{
		// Non-canonical but under a sensitive prefix: must never relay, and
		// must not reach the vendor either.
		{"generativelanguage.googleapis.com", "/v1beta/models/../../v1beta/xx:generateContent", ActionBlock,
			"dot segment escaping the gemini prefix while satisfying its Suffix rule"},
		{"generativelanguage.googleapis.com", "/v1beta/models/./x:generateContent", ActionBlock,
			"single-dot segment under the gemini prefix"},
		{"api.anthropic.com", "/v1/messages/../messages", ActionBlock,
			"dot segment under the anthropic sensitive prefix"},
		{"api.anthropic.com", "/api/../v1/messages", ActionBlock,
			"dot segment that dodges the raw prefix but resolves into it"},

		// Non-canonical and OUTSIDE every sensitive prefix: pass-through, as
		// before. These never go near the relay token; blocking them broke
		// Claude Code's own telemetry on nothing but a trailing slash.
		{"api.anthropic.com", "/api/event_logging/v2/batch/", ActionDirect, "trailing slash on a non-model route"},
		{"api.anthropic.com", "/api//claude_code_penguin_mode", ActionDirect, "doubled separator on a non-model route"},

		// Canonical and registered: unaffected.
		{"api.anthropic.com", "/v1/messages", ActionRelay, "the canonical relay route still works"},
		{"generativelanguage.googleapis.com", "/v1beta/models/gemini-2.5-pro:generateContent", ActionRelay,
			"the canonical gemini route still works"},
	} {
		if got := registry.Decide(tc.host, http.MethodPost, tc.path).Action; got != tc.want {
			t.Errorf("Decide(%s, POST, %s) = %v, want %v — %s", tc.host, tc.path, got, tc.want, tc.why)
		}
	}
}

// TestNormalizeHostStripsFQDNRootDot pins the trailing-dot bypass:
// "api.anthropic.com." resolves to the same origin as "api.anthropic.com", but
// the un-stripped form matched no target, so it slipped past both
// InterceptsHost (the relay loop guard, which would then have accepted the
// vendor as a relay upstream) and the routing allowlist (handing the tunnel to
// the vendor unfiltered).
func TestNormalizeHostStripsFQDNRootDot(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(DefaultTargets())
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{
		"api.anthropic.com.",
		"API.ANTHROPIC.COM.",
		"api.anthropic.com.:443",
	} {
		if !registry.InterceptsHost(host) {
			t.Errorf("InterceptsHost(%q) = false, want true — the trailing-dot form is the same origin", host)
		}
	}
	if registry.InterceptsHost("api.anthropic.com.evil.test") {
		t.Error("InterceptsHost matched a different domain that merely starts with an intercepted name")
	}
}

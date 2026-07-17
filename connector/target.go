// Package connector implements EveryAPI's process-scoped transparent HTTP
// connector. It keeps AI clients pointed at their vendors' official origins
// while relaying only explicitly registered model API routes to EveryAPI.
package connector

import (
	"fmt"
	"net"
	"net/http"
	stdpath "path"
	"strings"
)

// Action is the routing decision for one decrypted HTTP request.
type Action string

const (
	ActionDirect Action = "direct"
	ActionRelay  Action = "relay"
	ActionBlock  Action = "block"
)

// Route matches an HTTP method and path. Exact is mutually exclusive with
// Prefix and Suffix; when Prefix and Suffix are present both must match.
type Route struct {
	Method       string
	Exact        string
	Prefix       string
	Suffix       string
	Action       Action
	RejectStatus int
}

// Target describes one vendor origin. SensitivePrefixes are fail-closed: a
// request beneath one of them that is not explicitly relayed is blocked rather
// than accidentally reaching the vendor directly.
type Target struct {
	Name              string
	Hosts             []string
	Routes            []Route
	SensitivePrefixes []string
}

// Decision is the result of applying the registry to one request.
type Decision struct {
	Action       Action
	TargetName   string
	RejectStatus int
}

// Registry indexes immutable target definitions by normalized hostname.
type Registry struct {
	byHost map[string]*Target
}

func NewRegistry(targets []Target) (*Registry, error) {
	r := &Registry{byHost: make(map[string]*Target)}
	for i := range targets {
		owned := targets[i]
		owned.Hosts = append([]string(nil), targets[i].Hosts...)
		owned.Routes = append([]Route(nil), targets[i].Routes...)
		owned.SensitivePrefixes = append([]string(nil), targets[i].SensitivePrefixes...)
		target := &owned
		if target.Name == "" {
			return nil, fmt.Errorf("connector target name is required")
		}
		for routeIndex, route := range target.Routes {
			if route.Exact == "" && route.Prefix == "" && route.Suffix == "" {
				return nil, fmt.Errorf("connector target %q route %d has no path matcher", target.Name, routeIndex)
			}
			if route.Exact != "" && (route.Prefix != "" || route.Suffix != "") {
				return nil, fmt.Errorf("connector target %q route %d mixes exact and partial path matchers", target.Name, routeIndex)
			}
			switch route.Action {
			case ActionDirect, ActionRelay, ActionBlock:
			default:
				return nil, fmt.Errorf("connector target %q route %d has invalid action %q", target.Name, routeIndex, route.Action)
			}
			if route.RejectStatus != 0 {
				if route.Action != ActionBlock || route.RejectStatus < 400 || route.RejectStatus > 499 {
					return nil, fmt.Errorf("connector target %q route %d has invalid rejection status %d", target.Name, routeIndex, route.RejectStatus)
				}
			}
		}
		for _, rawHost := range target.Hosts {
			host := normalizeHost(rawHost)
			if host == "" {
				return nil, fmt.Errorf("connector target %q has an empty host", target.Name)
			}
			if previous, exists := r.byHost[host]; exists {
				return nil, fmt.Errorf("connector host %q is declared by both %q and %q", host, previous.Name, target.Name)
			}
			r.byHost[host] = target
		}
	}
	return r, nil
}

func (r *Registry) Decide(host, method, path string) Decision {
	if r == nil {
		return Decision{Action: ActionDirect}
	}
	target := r.byHost[normalizeHost(host)]
	if target == nil {
		return Decision{Action: ActionDirect}
	}
	// A path that is not already canonical can never satisfy the relay
	// allowlist. The allowlist matches the raw request path and roundTrip
	// forwards that same raw path, so a dot segment would otherwise satisfy a
	// Prefix rule while actually addressing somewhere else: POST
	// /v1beta/models/../../v1beta/xx:generateContent matched the gemini prefix
	// and was relayed with the token attached. No legitimate model API path
	// contains a dot segment, so skipping the route loop is free.
	//
	// It must NOT short-circuit the whole function, though: paths outside every
	// SensitivePrefix legitimately fall through to ActionDirect and never go
	// near the relay token. Blocking them outright broke ordinary vendor
	// traffic — Claude Code's own /api/event_logging/v2/batch/ and
	// /api/claude_cli/bootstrap/ 400'd on nothing but a trailing slash.
	cleaned := stdpath.Clean(path)
	canonical := cleaned == path
	method = strings.ToUpper(method)
	for _, route := range target.Routes {
		if !canonical {
			break
		}
		if route.Method != "" && strings.ToUpper(route.Method) != method {
			continue
		}
		if route.Exact != "" && path != route.Exact {
			continue
		}
		if route.Prefix != "" && !strings.HasPrefix(path, route.Prefix) {
			continue
		}
		if route.Suffix != "" && !strings.HasSuffix(path, route.Suffix) {
			continue
		}
		return Decision{Action: route.Action, TargetName: target.Name, RejectStatus: route.RejectStatus}
	}
	// Match sensitive prefixes against the raw AND the cleaned path. Raw alone
	// would let /api/../v1/messages dodge the /v1/messages prefix and reach the
	// vendor directly — the connector forwards the raw path and the vendor
	// normalizes it — which is the unregistered-model-route bypass these
	// prefixes exist to stop.
	for _, prefix := range target.SensitivePrefixes {
		if strings.HasPrefix(path, prefix) || strings.HasPrefix(cleaned, prefix) {
			return Decision{Action: ActionBlock, TargetName: target.Name}
		}
	}
	return Decision{Action: ActionDirect, TargetName: target.Name}
}

func (r *Registry) InterceptsHost(host string) bool {
	return r != nil && r.byHost[normalizeHost(host)] != nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	// Strip the FQDN root dot: "api.anthropic.com." and "api.anthropic.com"
	// resolve to the same origin, so leaving it on let the trailing-dot form
	// slip past both InterceptsHost (the relay loop guard) and the routing
	// allowlist, which would hand the tunnel to the vendor unfiltered.
	// A bare "." is the root and never a target host, so it is left alone.
	if len(host) > 1 {
		host = strings.TrimSuffix(host, ".")
	}
	return host
}

// DefaultTargets are protocol definitions, not client definitions. Any CLI,
// SDK, or desktop app using these official origins can share the connector.
func DefaultTargets() []Target {
	return []Target{
		{
			Name:  "anthropic",
			Hosts: []string{"api.anthropic.com"},
			Routes: []Route{
				{Method: http.MethodPost, Exact: "/v1/messages/count_tokens", Action: ActionRelay},
				{Method: http.MethodPost, Exact: "/v1/messages", Action: ActionRelay},
			},
			SensitivePrefixes: []string{"/v1/messages"},
		},
		{
			Name:  "openai",
			Hosts: []string{"api.openai.com"},
			Routes: []Route{
				{Method: http.MethodPost, Exact: "/v1/responses/compact", Action: ActionRelay},
				{Method: http.MethodPost, Exact: "/v1/responses", Action: ActionRelay},
				{Method: http.MethodGet, Exact: "/v1/responses", Action: ActionBlock, RejectStatus: http.StatusUpgradeRequired},
				{Method: http.MethodPost, Exact: "/v1/chat/completions", Action: ActionRelay},
				{Method: http.MethodPost, Exact: "/v1/completions", Action: ActionRelay},
				{Method: http.MethodPost, Exact: "/v1/embeddings", Action: ActionRelay},
			},
			SensitivePrefixes: []string{"/v1/"},
		},
		{
			Name:  "gemini",
			Hosts: []string{"generativelanguage.googleapis.com"},
			Routes: []Route{
				{Method: http.MethodPost, Prefix: "/v1beta/models/", Suffix: ":generateContent", Action: ActionRelay},
				{Method: http.MethodPost, Prefix: "/v1beta/models/", Suffix: ":streamGenerateContent", Action: ActionRelay},
				// Embeddings are a model API the gateway serves (its Gemini
				// adaptor emits :embedContent / :batchEmbedContents for
				// embedding models), so leaving them out of this allowlist made
				// SensitivePrefixes below fail-closed 403 them. That was
				// invisible while transparent mode was opt-in and became a
				// regression for every `everyapi use gemini` once it defaulted
				// on: the injected path has no route filter and relays them
				// fine. Compare the anthropic target, which relays
				// /v1/messages/count_tokens alongside /v1/messages for the same
				// reason.
				//
				// :countTokens is deliberately NOT here. The gateway rebuilds
				// the upstream URL from the model name and never emits that
				// action, so relaying it would forward a token-count request to
				// be answered as :generateContent. Fail-closed is the honest
				// outcome until the gateway can actually serve it.
				{Method: http.MethodPost, Prefix: "/v1beta/models/", Suffix: ":embedContent", Action: ActionRelay},
				{Method: http.MethodPost, Prefix: "/v1beta/models/", Suffix: ":batchEmbedContents", Action: ActionRelay},
			},
			SensitivePrefixes: []string{"/v1beta/models/"},
		},
	}
}

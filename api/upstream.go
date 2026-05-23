// Upstream-status SDK: GET /api/upstream-status. A public,
// Statuspage-style health rollup of the upstream providers the gateway
// relays to (OpenAI / Anthropic / etc.). No auth — construct the
// Client with an empty token (api.New(base, "")).
package api

import (
	"context"
	"errors"
)

// UpstreamComponent is one non-operational sub-component of a provider
// (only degraded/outage components are returned by the backend).
type UpstreamComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"` // operational | degraded_performance | partial_outage | major_outage | under_maintenance
}

// UpstreamIncident is one active incident on a provider's status page.
type UpstreamIncident struct {
	Name      string `json:"name"`
	Status    string `json:"status"` // investigating | identified | monitoring | resolved
	Impact    string `json:"impact"` // none | minor | major | critical
	UpdatedAt string `json:"updated_at"`
}

// UpstreamProvider is one provider's current health. Indicator is the
// Statuspage vocab: none (green) | minor (yellow) | major | critical
// (red) | unknown. Components / Incidents are present only when
// non-empty. FetchedAt is unix seconds; 0 means never fetched yet.
type UpstreamProvider struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Short       string              `json:"short"`
	StatusURL   string              `json:"status_url"`
	Indicator   string              `json:"indicator"`
	Description string              `json:"description"`
	Components  []UpstreamComponent `json:"components"`
	Incidents   []UpstreamIncident  `json:"incidents"`
	FetchedAt   int64               `json:"fetched_at"`
}

// GetUpstreamStatus reads the public GET /api/upstream-status. The
// backend caches the snapshot ~60s, so polling tighter than that just
// returns the same data.
func (c *Client) GetUpstreamStatus(ctx context.Context) ([]UpstreamProvider, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Providers []UpstreamProvider `json:"providers"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/upstream-status", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data.Providers, nil
}

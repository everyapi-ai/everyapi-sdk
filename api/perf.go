// Performance-metrics SDK: GET /api/perf-metrics/summary. A per-model
// rollup (latency / success rate / throughput) of the gateway's own
// relay traffic — complements GetUpstreamStatus (provider-side health).
// The endpoint is TryUserAuth (login optional); the summary is a global
// aggregate, so an empty bearer works.
package api

import (
	"context"
	"errors"
	"net/url"
	"strconv"
)

// ModelPerf is one model's performance summary. AvgLatencyMs is the
// mean end-to-end latency; SuccessRate is a percentage (0–100); AvgTps
// is output tokens/sec; RequestCount is the sample size over the window.
type ModelPerf struct {
	ModelName    string  `json:"model_name"`
	AvgLatencyMs int64   `json:"avg_latency_ms"`
	SuccessRate  float64 `json:"success_rate"`
	AvgTps       float64 `json:"avg_tps"`
	RequestCount int64   `json:"request_count"`
}

// GetPerfSummary reads GET /api/perf-metrics/summary for the last
// `hours` (<=0 lets the backend default to 24h).
func (c *Client) GetPerfSummary(ctx context.Context, hours int) ([]ModelPerf, error) {
	path := "/api/perf-metrics/summary"
	if hours > 0 {
		path += "?" + url.Values{"hours": {strconv.Itoa(hours)}}.Encode()
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Models []ModelPerf `json:"models"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", path, nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data.Models, nil
}

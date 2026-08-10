package api

import (
	"context"
	"errors"
)

type ModelRoutingProviderSetting struct {
	KindSlug string `json:"kind_slug"`
	Model    string `json:"model,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type ModelRoutingSetting struct {
	Mode      string                        `json:"mode"`
	Providers []ModelRoutingProviderSetting `json:"providers"`
}

type ModelRoutingProvider struct {
	KindSlug    string  `json:"kind_slug"`
	Name        string  `json:"name"`
	Model       string  `json:"model,omitempty"`
	LatencyMS   int     `json:"latency_ms"`
	SuccessRate float64 `json:"success_rate"`
	Enabled     bool    `json:"enabled"`
	Available   bool    `json:"available"`
}

type ModelRoutingView struct {
	Mode      string                 `json:"mode"`
	Providers []ModelRoutingProvider `json:"providers"`
}

func (c *Client) GetModelRouting(ctx context.Context) (*ModelRoutingView, error) {
	return c.modelRoutingRequest(ctx, "GET", nil)
}

func (c *Client) UpdateModelRouting(ctx context.Context, setting ModelRoutingSetting) (*ModelRoutingView, error) {
	return c.modelRoutingRequest(ctx, "PUT", setting)
}

func (c *Client) modelRoutingRequest(ctx context.Context, method string, body any) (*ModelRoutingView, error) {
	var envelope struct {
		Success bool             `json:"success"`
		Message string           `json:"message"`
		Data    ModelRoutingView `json:"data"`
	}
	if err := c.do(ctx, method, "/api/user/model-routing", body, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

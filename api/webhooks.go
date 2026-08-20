package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// WebhookEvent is an outbound webhook subscription event. It remains an open
// string contract so an older SDK can use event names advertised by a newer
// gateway through WebhookEndpointList.AvailableEvents.
type WebhookEvent string

const (
	WebhookEventBalanceLow            WebhookEvent = "balance.low"
	WebhookEventChannelDisabled       WebhookEvent = "channel.disabled"
	WebhookEventSellerEarningsChanged WebhookEvent = "seller.earnings_changed"
	WebhookEventTokenBudgetExceeded   WebhookEvent = "token.budget_exceeded"
	WebhookEventAgentSessionCreated   WebhookEvent = "agent_session.created"
)

// WebhookEndpoint is the caller-owned outbound destination. Its signing secret
// is intentionally absent; the gateway returns that value only from create.
type WebhookEndpoint struct {
	ID             int            `json:"id"`
	URL            string         `json:"url"`
	Events         []WebhookEvent `json:"events"`
	Enabled        bool           `json:"enabled"`
	Description    string         `json:"description"`
	CreatedAt      int64          `json:"created_at"`
	UpdatedAt      int64          `json:"updated_at"`
	LastDeliveryAt *int64         `json:"last_delivery_at"`
}

type WebhookEndpointList struct {
	Endpoints       []WebhookEndpoint `json:"endpoints"`
	AvailableEvents []WebhookEvent    `json:"available_events"`
}

type WebhookEndpointCreate struct {
	URL         string         `json:"url"`
	Events      []WebhookEvent `json:"events"`
	Enabled     *bool          `json:"enabled,omitempty"`
	Description string         `json:"description,omitempty"`
}

type WebhookEndpointCreated struct {
	Endpoint WebhookEndpoint `json:"endpoint"`
	Secret   string          `json:"secret"`
}

// WebhookEndpointUpdate is a partial update. Nil fields remain unchanged;
// empty pointed-to values are sent verbatim for server-side validation.
type WebhookEndpointUpdate struct {
	URL         *string         `json:"url,omitempty"`
	Events      *[]WebhookEvent `json:"events,omitempty"`
	Enabled     *bool           `json:"enabled,omitempty"`
	Description *string         `json:"description,omitempty"`
}

type WebhookDelivery struct {
	ID         int          `json:"id"`
	EndpointID int          `json:"endpoint_id"`
	UserID     int          `json:"user_id"`
	EventType  WebhookEvent `json:"event_type"`
	Payload    string       `json:"payload"`
	StatusCode int          `json:"status_code"`
	Success    bool         `json:"success"`
	Attempts   int          `json:"attempts"`
	Error      string       `json:"error"`
	CreatedAt  int64        `json:"created_at"`
}

func webhookEndpointPath(endpointID int, suffix string) (string, error) {
	if endpointID <= 0 {
		return "", errors.New("webhook endpoint id must be positive")
	}
	return "/api/user/webhooks/" + strconv.Itoa(endpointID) + suffix, nil
}

func (c *Client) ListWebhookEndpoints(ctx context.Context) (*WebhookEndpointList, error) {
	var envelope struct {
		Success bool                `json:"success"`
		Message string              `json:"message"`
		Data    WebhookEndpointList `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/user/webhooks", nil, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

func (c *Client) CreateWebhookEndpoint(ctx context.Context, input WebhookEndpointCreate) (*WebhookEndpointCreated, error) {
	var envelope struct {
		Success bool                   `json:"success"`
		Message string                 `json:"message"`
		Data    WebhookEndpointCreated `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/user/webhooks", input, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

func (c *Client) UpdateWebhookEndpoint(ctx context.Context, endpointID int, input WebhookEndpointUpdate) (*WebhookEndpoint, error) {
	path, err := webhookEndpointPath(endpointID, "")
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Success bool            `json:"success"`
		Message string          `json:"message"`
		Data    WebhookEndpoint `json:"data"`
	}
	if err := c.do(ctx, http.MethodPut, path, input, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

func (c *Client) DeleteWebhookEndpoint(ctx context.Context, endpointID int) error {
	path, err := webhookEndpointPath(endpointID, "")
	if err != nil {
		return err
	}
	var envelope struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Deleted bool `json:"deleted"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodDelete, path, nil, &envelope); err != nil {
		return err
	}
	if !envelope.Success {
		return errors.New(envelope.Message)
	}
	if !envelope.Data.Deleted {
		return errors.New("webhook endpoint delete was not confirmed")
	}
	return nil
}

func (c *Client) ListWebhookDeliveries(ctx context.Context, endpointID, limit int) ([]WebhookDelivery, error) {
	path, err := webhookEndpointPath(endpointID, "/deliveries")
	if err != nil {
		return nil, err
	}
	if limit < 0 {
		return nil, errors.New("webhook delivery limit cannot be negative")
	}
	if limit > 200 {
		limit = 200
	}
	if limit > 0 {
		values := url.Values{"limit": {strconv.Itoa(limit)}}
		path += "?" + values.Encode()
	}
	var envelope struct {
		Success bool              `json:"success"`
		Message string            `json:"message"`
		Data    []WebhookDelivery `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return envelope.Data, nil
}

func (c *Client) TestWebhookEndpoint(ctx context.Context, endpointID int, event WebhookEvent) (*WebhookDelivery, error) {
	path, err := webhookEndpointPath(endpointID, "/test")
	if err != nil {
		return nil, err
	}
	body := struct {
		Event WebhookEvent `json:"event,omitempty"`
	}{Event: event}
	var envelope struct {
		Success bool            `json:"success"`
		Message string          `json:"message"`
		Data    WebhookDelivery `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, path, body, &envelope); err != nil {
		return nil, err
	}
	if !envelope.Success {
		return nil, errors.New(envelope.Message)
	}
	return &envelope.Data, nil
}

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestListWebhookEndpointsDecodesAvailableEventsWithoutSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/user/webhooks" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer acc" || r.Header.Get("EveryAPI-User-Id") != "9" {
			t.Fatalf("auth headers missing: %#v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"endpoints":[{"id":7,"url":"https://hooks.example.com/everyapi","events":["channel.disabled","balance.low"],"enabled":true,"description":"ops","created_at":100,"updated_at":101,"last_delivery_at":102}],"available_events":["balance.low","channel.disabled","seller.earnings_changed","token.budget_exceeded","agent_session.created"]}}`))
	}))
	defer server.Close()

	got, err := New(server.URL, "acc").WithUserID(9).ListWebhookEndpoints(context.Background())
	if err != nil {
		t.Fatalf("ListWebhookEndpoints: %v", err)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].ID != 7 || got.Endpoints[0].LastDeliveryAt == nil || *got.Endpoints[0].LastDeliveryAt != 102 {
		t.Fatalf("endpoints = %+v", got.Endpoints)
	}
	if len(got.AvailableEvents) != 5 || got.AvailableEvents[4] != WebhookEventAgentSessionCreated {
		t.Fatalf("available events = %#v", got.AvailableEvents)
	}
}

func TestCreateWebhookEndpointReturnsOneTimeSecret(t *testing.T) {
	enabled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/user/webhooks" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var body WebhookEndpointCreate
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.URL != "https://hooks.example.com/everyapi" || len(body.Events) != 1 || body.Events[0] != WebhookEventChannelDisabled || body.Enabled == nil || *body.Enabled {
			t.Fatalf("body = %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"endpoint":{"id":8,"url":"https://hooks.example.com/everyapi","events":["channel.disabled"],"enabled":false,"description":"ops","created_at":100,"updated_at":100,"last_delivery_at":null},"secret":"eawh_one-time"}}`))
	}))
	defer server.Close()

	got, err := New(server.URL, "acc").WithUserID(9).CreateWebhookEndpoint(context.Background(), WebhookEndpointCreate{
		URL: "https://hooks.example.com/everyapi", Events: []WebhookEvent{WebhookEventChannelDisabled},
		Enabled: &enabled, Description: "ops",
	})
	if err != nil {
		t.Fatalf("CreateWebhookEndpoint: %v", err)
	}
	if got.Endpoint.ID != 8 || got.Secret != "eawh_one-time" {
		t.Fatalf("created = %+v", got)
	}
}

func TestUpdateAndDeleteWebhookEndpointUseOwnedEndpointPath(t *testing.T) {
	url := "https://hooks.example.com/v2"
	events := []WebhookEvent{WebhookEventSellerEarningsChanged}
	description := "finance"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/user/webhooks/12" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPut:
			var body WebhookEndpointUpdate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.URL == nil || *body.URL != url || body.Events == nil || len(*body.Events) != 1 || (*body.Events)[0] != WebhookEventSellerEarningsChanged || body.Description == nil || *body.Description != description {
				t.Fatalf("body = %+v", body)
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":12,"url":"https://hooks.example.com/v2","events":["seller.earnings_changed"],"enabled":true,"description":"finance","created_at":100,"updated_at":110,"last_delivery_at":null}}`))
		case http.MethodDelete:
			_, _ = w.Write([]byte(`{"success":true,"data":{"deleted":true}}`))
		default:
			t.Fatalf("method = %s", r.Method)
		}
	}))
	defer server.Close()

	client := New(server.URL, "acc").WithUserID(9)
	updated, err := client.UpdateWebhookEndpoint(context.Background(), 12, WebhookEndpointUpdate{
		URL: &url, Events: &events, Description: &description,
	})
	if err != nil {
		t.Fatalf("UpdateWebhookEndpoint: %v", err)
	}
	if updated.ID != 12 || updated.Description != description {
		t.Fatalf("updated = %+v", updated)
	}
	if err := client.DeleteWebhookEndpoint(context.Background(), 12); err != nil {
		t.Fatalf("DeleteWebhookEndpoint: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestWebhookDeliveryMethodsDecodeBoundedHistoryAndTestResult(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/user/webhooks/15/deliveries":
			if r.URL.Query().Get("limit") != "200" {
				t.Fatalf("limit = %q", r.URL.Query().Get("limit"))
			}
			_, _ = w.Write([]byte(`{"success":true,"data":[{"id":21,"endpoint_id":15,"user_id":9,"event_type":"channel.disabled","payload":"{\"event\":\"channel.disabled\"}","status_code":204,"success":true,"attempts":1,"error":"","created_at":120}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/user/webhooks/15/test":
			var body struct {
				Event WebhookEvent `json:"event"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Event != WebhookEventChannelDisabled {
				t.Fatalf("event = %q", body.Event)
			}
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":22,"endpoint_id":15,"user_id":9,"event_type":"channel.disabled","payload":"{}","status_code":500,"success":false,"attempts":3,"error":"non-2xx status code: 500","created_at":121}}`))
		default:
			t.Fatalf("request = %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := New(server.URL, "acc").WithUserID(9)
	deliveries, err := client.ListWebhookDeliveries(context.Background(), 15, 999)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	if len(deliveries) != 1 || deliveries[0].StatusCode != 204 || deliveries[0].EventType != WebhookEventChannelDisabled {
		t.Fatalf("deliveries = %+v", deliveries)
	}
	tested, err := client.TestWebhookEndpoint(context.Background(), 15, WebhookEventChannelDisabled)
	if err != nil {
		t.Fatalf("TestWebhookEndpoint: %v", err)
	}
	if tested.Success || tested.Attempts != 3 || tested.Error == "" {
		t.Fatalf("tested = %+v", tested)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestWebhookMethodsRejectInvalidEndpointIDAndLimitWithoutNetwork(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	client := New(server.URL, "acc").WithUserID(9)
	if _, err := client.UpdateWebhookEndpoint(context.Background(), 0, WebhookEndpointUpdate{}); err == nil {
		t.Fatal("UpdateWebhookEndpoint accepted endpoint id 0")
	}
	if err := client.DeleteWebhookEndpoint(context.Background(), -1); err == nil {
		t.Fatal("DeleteWebhookEndpoint accepted a negative endpoint id")
	}
	if _, err := client.ListWebhookDeliveries(context.Background(), 1, -1); err == nil {
		t.Fatal("ListWebhookDeliveries accepted a negative limit")
	}
	if _, err := client.TestWebhookEndpoint(context.Background(), 0, WebhookEventChannelDisabled); err == nil {
		t.Fatal("TestWebhookEndpoint accepted endpoint id 0")
	}
	if hits.Load() != 0 {
		t.Fatalf("invalid input reached the network %d time(s)", hits.Load())
	}
}

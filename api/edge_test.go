package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateEdgeNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/seller/edge/nodes" {
			t.Fatalf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		var req EdgeNodeCreate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.Name != "rtx-4090-tokyo" {
			t.Fatalf("unexpected name: %q", req.Name)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": EdgeNodeRegistration{
				Node:              EdgeNode{ID: 42, Name: req.Name, Status: "offline"},
				RegistrationToken: "rt_abc123",
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "sk-test")
	out, err := c.CreateEdgeNode(context.Background(), EdgeNodeCreate{Name: "rtx-4090-tokyo"})
	if err != nil {
		t.Fatalf("CreateEdgeNode: %v", err)
	}
	if out.Node.ID != 42 || out.RegistrationToken != "rt_abc123" {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestListEdgeNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"items": []EdgeNode{
					{ID: 1, Name: "a", Status: "online"},
					{ID: 2, Name: "b", Status: "offline"},
				},
			},
		})
	}))
	defer srv.Close()

	nodes, err := New(srv.URL, "sk-test").ListEdgeNodes(context.Background())
	if err != nil {
		t.Fatalf("ListEdgeNodes: %v", err)
	}
	if len(nodes) != 2 || nodes[0].ID != 1 || nodes[1].Status != "offline" {
		t.Fatalf("unexpected: %+v", nodes)
	}
}

func TestGetEdgeNodeFiltersList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"items": []EdgeNode{{ID: 7, Name: "needle"}, {ID: 8, Name: "haystack"}},
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, "sk-test")
	got, err := c.GetEdgeNode(context.Background(), 7)
	if err != nil {
		t.Fatalf("GetEdgeNode: %v", err)
	}
	if got.Name != "needle" {
		t.Fatalf("wrong node: %+v", got)
	}
	if _, err := c.GetEdgeNode(context.Background(), 999); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestSetEdgeNodeStatus(t *testing.T) {
	gotMethod := ""
	gotPath := ""
	gotStatus := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		var body struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotStatus = body.Status
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer srv.Close()

	if err := New(srv.URL, "sk-test").SetEdgeNodeStatus(context.Background(), 42, "paused"); err != nil {
		t.Fatalf("SetEdgeNodeStatus: %v", err)
	}
	if gotMethod != "PATCH" || gotPath != "/api/seller/edge/nodes/42/status" || gotStatus != "paused" {
		t.Fatalf("wrong req: %s %s status=%q", gotMethod, gotPath, gotStatus)
	}
}

func TestDeleteEdgeNode(t *testing.T) {
	gotPath := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer srv.Close()

	if err := New(srv.URL, "sk-test").DeleteEdgeNode(context.Background(), 42); err != nil {
		t.Fatalf("DeleteEdgeNode: %v", err)
	}
	if gotPath != "/api/seller/edge/nodes/42" {
		t.Fatalf("wrong path: %s", gotPath)
	}
}

func TestEdgeNodeErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"message": "Channel mount cap reached (10).",
		})
	}))
	defer srv.Close()

	_, err := New(srv.URL, "sk-test").CreateEdgeNode(context.Background(), EdgeNodeCreate{Name: "x"})
	if err == nil {
		t.Fatal("expected error from success=false envelope")
	}
}

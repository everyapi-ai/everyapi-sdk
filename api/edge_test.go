package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateEdgeNode(t *testing.T) {
	// Decode the request against an inline struct that mirrors the
	// BACKEND-side wire format (backend/pkg/edge.Location uses
	// `country_iso2`, not `country`). Decoding into the SDK's own
	// EdgeNodeCreate would round-trip cleanly even if the SDK reverted
	// to the buggy `country` tag, so the contract test would silently
	// pass while real registers drop the field on the wire.
	gotLocation := struct {
		CountryISO2 string `json:"country_iso2"`
		Region      string `json:"region"`
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/seller/edge/nodes" {
			t.Fatalf("unexpected req: %s %s", r.Method, r.URL.Path)
		}
		var req struct {
			Name     string `json:"name"`
			Location *struct {
				CountryISO2 string `json:"country_iso2"`
				Region      string `json:"region"`
			} `json:"location"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.Name != "rtx-4090-tokyo" {
			t.Fatalf("unexpected name: %q", req.Name)
		}
		if req.Location != nil {
			gotLocation = *req.Location
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
	out, err := c.CreateEdgeNode(context.Background(), EdgeNodeCreate{
		Name:     "rtx-4090-tokyo",
		Location: &EdgeLoc{CountryISO2: "JP", Region: "tokyo"},
	})
	if err != nil {
		t.Fatalf("CreateEdgeNode: %v", err)
	}
	if out.Node.ID != 42 || out.RegistrationToken != "rt_abc123" {
		t.Fatalf("unexpected: %+v", out)
	}
	if gotLocation.CountryISO2 != "JP" || gotLocation.Region != "tokyo" {
		t.Fatalf("location dropped on wire: %+v", gotLocation)
	}
}

// TestEdgeLocFullWireFormat pins every Location field on the wire,
// not just country_iso2 + region. The round-1 fix expanded EdgeLoc to
// include Latitude/Longitude (matching backend pkg/edge.Location);
// without this test a typo like `json:"lattitude"` would round-trip
// cleanly through the SDK's own struct and reach prod silently,
// exactly the failure mode the original country/country_iso2 drift
// hit. Decodes against an inline backend-shape struct on purpose.
func TestEdgeLocFullWireFormat(t *testing.T) {
	want := struct {
		CountryISO2 string  `json:"country_iso2"`
		Region      string  `json:"region"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var req struct {
			Location *struct {
				CountryISO2 string  `json:"country_iso2"`
				Region      string  `json:"region"`
				Latitude    float64 `json:"latitude"`
				Longitude   float64 `json:"longitude"`
			} `json:"location"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Location != nil {
			want = *req.Location
		}
	}))
	defer srv.Close()

	_, _ = New(srv.URL, "sk-test").CreateEdgeNode(context.Background(), EdgeNodeCreate{
		Name: "tokyo-rig",
		Location: &EdgeLoc{
			CountryISO2: "JP",
			Region:      "tokyo",
			Latitude:    35.6762,
			Longitude:   139.6503,
		},
	})

	if want.CountryISO2 != "JP" || want.Region != "tokyo" {
		t.Fatalf("country/region dropped: %+v", want)
	}
	if want.Latitude != 35.6762 || want.Longitude != 139.6503 {
		t.Fatalf("lat/long dropped — likely a JSON tag typo on EdgeLoc: %+v", want)
	}
}

// TestEdgeHWFullWireFormat is the same drift guard for EdgeHW. Hardware
// is agent-reported and decoded on the read path (list / status); a tag
// typo would silently zero the field in dashboard renders. We exercise
// the decode side by replaying a backend-shaped JSON payload into the
// SDK's ListEdgeNodes and asserting every field round-trips.
func TestEdgeHWFullWireFormat(t *testing.T) {
	const hwJSON = `{
		"gpu_model":     "NVIDIA GeForce RTX 4090",
		"gpu_count":     2,
		"vram_total_gb": 48,
		"cuda_version":  "12.4",
		"driver":        "550.54.15",
		"cpu_model":     "AMD Ryzen 9 7950X",
		"ram_total_gb":  128,
		"platform":      "linux/amd64"
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := `{"success":true,"data":{"items":[{"id":1,"name":"n","status":"online","hardware":` + hwJSON + `}]}}`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	nodes, err := New(srv.URL, "sk-test").ListEdgeNodes(context.Background())
	if err != nil {
		t.Fatalf("ListEdgeNodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Hardware == nil {
		t.Fatalf("expected one node with hardware decoded, got %+v", nodes)
	}
	hw := nodes[0].Hardware
	if hw.GPUModel != "NVIDIA GeForce RTX 4090" {
		t.Errorf("gpu_model dropped: %q", hw.GPUModel)
	}
	if hw.GPUCount != 2 {
		t.Errorf("gpu_count dropped: %d", hw.GPUCount)
	}
	if hw.VRAMTotalGB != 48 {
		t.Errorf("vram_total_gb dropped: %d", hw.VRAMTotalGB)
	}
	if hw.CUDAVersion != "12.4" {
		t.Errorf("cuda_version dropped: %q", hw.CUDAVersion)
	}
	if hw.Driver != "550.54.15" {
		t.Errorf("driver dropped: %q", hw.Driver)
	}
	if hw.CPUModel != "AMD Ryzen 9 7950X" {
		t.Errorf("cpu_model dropped: %q", hw.CPUModel)
	}
	if hw.RAMTotalGB != 128 {
		t.Errorf("ram_total_gb dropped: %d", hw.RAMTotalGB)
	}
	if hw.Platform != "linux/amd64" {
		t.Errorf("platform dropped: %q", hw.Platform)
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
	// Cover both action values — a typo like
	// `EdgeNodeActionEnable = "enabled"` (the buggy SDK shape we
	// fixed) would slip past a single-value test.
	cases := []struct {
		name       string
		action     EdgeNodeAction
		wantAction string
	}{
		{"disable", EdgeNodeActionDisable, "disable"},
		{"enable", EdgeNodeActionEnable, "enable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMethod := ""
			gotPath := ""
			gotAction := ""
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				// Decode against the BACKEND-side shape
				// (action: enable|disable), not the SDK's own struct
				// — a regression that reintroduces the old
				// {"status":"paused"} payload would round-trip
				// cleanly through the SDK's own struct and slip past
				// the test.
				var body struct {
					Action string `json:"action"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				gotAction = body.Action
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
			}))
			defer srv.Close()

			if err := New(srv.URL, "sk-test").SetEdgeNodeStatus(context.Background(), 42, tc.action); err != nil {
				t.Fatalf("SetEdgeNodeStatus: %v", err)
			}
			if gotMethod != "PATCH" || gotPath != "/api/seller/edge/nodes/42/status" || gotAction != tc.wantAction {
				t.Fatalf("wrong req: %s %s action=%q (wanted %q)", gotMethod, gotPath, gotAction, tc.wantAction)
			}
		})
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

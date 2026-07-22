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

// TestEdgeNodeTelemetryWireFormat pins the live-telemetry fields on
// EdgeNode (gpu_util_pct / vram_used_gb / active_requests) plus
// created_at — the backend's edgeNodeView surfaces them but the SDK
// originally only decoded the static metadata. Same drift-guard
// shape as TestEdgeHWFullWireFormat: replay a backend-shaped JSON
// blob into ListEdgeNodes and assert every field round-trips with
// the right TYPE (the omitempty pointers distinguish "not reported"
// nil from a meaningful zero value).
func TestEdgeNodeTelemetryWireFormat(t *testing.T) {
	const nodeJSON = `{
		"id":              1,
		"name":            "n",
		"status":          "online",
		"channel_id":      null,
		"paused":          false,
		"last_seen_at":    1700000000,
		"created_at":      1699000000,
		"gpu_util_pct":    73,
		"vram_used_gb":    18.5,
		"active_requests": 4
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := `{"success":true,"data":{"items":[` + nodeJSON + `]}}`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	nodes, err := New(srv.URL, "sk-test").ListEdgeNodes(context.Background())
	if err != nil {
		t.Fatalf("ListEdgeNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.CreatedAt != 1699000000 {
		t.Errorf("created_at dropped: %d", n.CreatedAt)
	}
	if n.GPUUtilPct == nil || *n.GPUUtilPct != 73 {
		t.Errorf("gpu_util_pct dropped: got %+v", n.GPUUtilPct)
	}
	if n.VRAMUsedGB == nil || *n.VRAMUsedGB != 18.5 {
		t.Errorf("vram_used_gb dropped: got %+v", n.VRAMUsedGB)
	}
	if n.ActiveRequests == nil || *n.ActiveRequests != 4 {
		t.Errorf("active_requests dropped: got %+v", n.ActiveRequests)
	}
}

// TestEdgeNodeTelemetryPartialReport pins the per-field decode shape:
// the current backend (viewEdgeNode in edge_node.go) assigns all
// three live fields together off the same heartbeat snapshot, so a
// mixed-nil response can't happen today. But the CLI and MCP
// renderers branch per-field on nil, on the (defensive) assumption
// that a future backend split — e.g. active_requests becoming
// optional or computed elsewhere — might emit only some of the
// three. This test pins that behavior: when the backend reports
// only gpu_util_pct, the SDK MUST leave the other two pointers nil
// so renderers omit them cleanly rather than rendering 0.
func TestEdgeNodeTelemetryPartialReport(t *testing.T) {
	const nodeJSON = `{
		"id":           3,
		"name":         "partial-rig",
		"status":       "online",
		"channel_id":   null,
		"paused":       false,
		"last_seen_at": 1700000000,
		"gpu_util_pct": 42
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := `{"success":true,"data":{"items":[` + nodeJSON + `]}}`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	nodes, err := New(srv.URL, "sk-test").ListEdgeNodes(context.Background())
	if err != nil {
		t.Fatalf("ListEdgeNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.GPUUtilPct == nil || *n.GPUUtilPct != 42 {
		t.Errorf("gpu_util_pct must round-trip; got %+v", n.GPUUtilPct)
	}
	if n.VRAMUsedGB != nil {
		t.Errorf("vram_used_gb must stay nil when backend omits it; got %g", *n.VRAMUsedGB)
	}
	if n.ActiveRequests != nil {
		t.Errorf("active_requests must stay nil when backend omits it; got %d", *n.ActiveRequests)
	}
}

// TestEdgeNodeTelemetryZeroValuesOnIdleNode is the missing-vs-zero
// contract test the SDK doc and specs/edge-node.md rest on. The backend
// viewEdgeNode assigns the three live pointers inside its
// `ReceivedAt > 0` branch unconditionally, so an idle but
// online+heartbeating node emits e.g. `gpu_util_pct: 0` — the JSON
// key is PRESENT with value 0, NOT omitted. The SDK must surface
// `*GPUUtilPct == 0` (non-nil pointer to zero), distinct from the
// offline case where the key is omitted entirely (nil pointer).
// Without this, a CLI / dashboard rendering "GPU 0%" for a busy
// node and "no live data" for an idle one would collapse into the
// same nil branch and the seller would lose the distinction.
func TestEdgeNodeTelemetryZeroValuesOnIdleNode(t *testing.T) {
	const nodeJSON = `{
		"id":              4,
		"name":            "idle-rig",
		"status":          "online",
		"channel_id":      null,
		"paused":          false,
		"last_seen_at":    1700000000,
		"gpu_util_pct":    0,
		"vram_used_gb":    0.0,
		"active_requests": 0
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := `{"success":true,"data":{"items":[` + nodeJSON + `]}}`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	nodes, err := New(srv.URL, "sk-test").ListEdgeNodes(context.Background())
	if err != nil {
		t.Fatalf("ListEdgeNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.GPUUtilPct == nil {
		t.Fatal("gpu_util_pct=0 in JSON must NOT decode to nil pointer (would collapse with offline case)")
	}
	if *n.GPUUtilPct != 0 {
		t.Errorf("gpu_util_pct: expected 0, got %d", *n.GPUUtilPct)
	}
	if n.VRAMUsedGB == nil {
		t.Fatal("vram_used_gb=0 in JSON must NOT decode to nil pointer")
	}
	if *n.VRAMUsedGB != 0 {
		t.Errorf("vram_used_gb: expected 0, got %g", *n.VRAMUsedGB)
	}
	if n.ActiveRequests == nil {
		t.Fatal("active_requests=0 in JSON must NOT decode to nil pointer")
	}
	if *n.ActiveRequests != 0 {
		t.Errorf("active_requests: expected 0, got %d", *n.ActiveRequests)
	}
}

// TestEdgeNodeTelemetryNilOnOfflineNode pins the offline rendering
// path: when the backend omits the telemetry fields (omitempty,
// matches the "node is offline / no heartbeat yet" branch in
// viewEdgeNode), the SDK pointers must remain nil so CLI / dashboard
// renderers can distinguish "no live data" from "0% util".
func TestEdgeNodeTelemetryNilOnOfflineNode(t *testing.T) {
	const nodeJSON = `{
		"id":           2,
		"name":         "offline-rig",
		"status":       "offline",
		"channel_id":   null,
		"paused":       false,
		"last_seen_at": 0
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := `{"success":true,"data":{"items":[` + nodeJSON + `]}}`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	nodes, err := New(srv.URL, "sk-test").ListEdgeNodes(context.Background())
	if err != nil {
		t.Fatalf("ListEdgeNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.GPUUtilPct != nil {
		t.Errorf("gpu_util_pct must be nil for offline node; got %d", *n.GPUUtilPct)
	}
	if n.VRAMUsedGB != nil {
		t.Errorf("vram_used_gb must be nil for offline node; got %g", *n.VRAMUsedGB)
	}
	if n.ActiveRequests != nil {
		t.Errorf("active_requests must be nil for offline node; got %d", *n.ActiveRequests)
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

func TestUpdateEdgeNode(t *testing.T) {
	// Decode against the BACKEND-side wire format (the controller's
	// edgeNodeUpdateRequest{Name, Location} in
	// backend/internal/transport/http/edge/node.go) — decoding into the
	// SDK's own EdgeNodeUpdate would round-trip cleanly even if a
	// future SDK rename desynchronised the JSON tags, masking the
	// drift this test is meant to catch.
	var gotMethod, gotPath, gotName string
	var gotLocCountry, gotLocRegion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		var body struct {
			Name     string `json:"name"`
			Location *struct {
				CountryISO2 string `json:"country_iso2"`
				Region      string `json:"region"`
			} `json:"location"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotName = body.Name
		if body.Location != nil {
			gotLocCountry = body.Location.CountryISO2
			gotLocRegion = body.Location.Region
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	defer srv.Close()

	c := New(srv.URL, "sk-test")
	err := c.UpdateEdgeNode(context.Background(), 42, EdgeNodeUpdate{
		Name:     "renamed",
		Location: &EdgeLoc{CountryISO2: "JP", Region: "tokyo"},
	})
	if err != nil {
		t.Fatalf("UpdateEdgeNode: %v", err)
	}
	if gotMethod != "PUT" || gotPath != "/api/seller/edge/nodes/42" {
		t.Fatalf("wrong req: %s %s", gotMethod, gotPath)
	}
	if gotName != "renamed" {
		t.Fatalf("name not on wire: got %q", gotName)
	}
	if gotLocCountry != "JP" || gotLocRegion != "tokyo" {
		t.Fatalf("location not on wire: country=%q region=%q", gotLocCountry, gotLocRegion)
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

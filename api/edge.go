// Edge-node management surfaces — the seller-side endpoints under
// /api/seller/edge/nodes that the CLI's `everyapi edge ...` command
// group consumes. Shapes mirror backend/internal/transport/http/edge/node.go's
// edgeNodeView + edgeNodeCreateResponse but only decode what we render,
// so a future backend field addition doesn't break this client.
package api

import (
	"context"
	"errors"
	"fmt"
)

// EdgeNode is the seller-facing view of a registered BYO-GPU node.
// Status is the string form of pkg/edge.NodeStatus ("offline" /
// "online" / "disabled"); the dashboard and CLI both match on these
// strings, so renaming on the backend would break tooling.
//
// GPUUtilPct / VRAMUsedGB / ActiveRequests are live-telemetry pointers:
// the backend (backend/internal/transport/http/edge/node.go::viewEdgeNode)
// omits them when the node is offline or hasn't reported a heartbeat
// yet — the dashboard treats nil as "no live data" rather than
// surfacing 0 (a 0% util reading from an idle node IS meaningful,
// so the missing-vs-zero distinction matters). CLI renderers should
// gate display on the pointer being non-nil.
type EdgeNode struct {
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	Status         string   `json:"status"`
	ChannelID      *int     `json:"channel_id"`
	Paused         bool     `json:"paused"`
	Hardware       *EdgeHW  `json:"hardware,omitempty"`
	Location       *EdgeLoc `json:"location,omitempty"`
	Models         []string `json:"models,omitempty"`
	Workloads      []string `json:"workloads,omitempty"`
	AgentVer       string   `json:"agent_version,omitempty"`
	LastSeenAt     int64    `json:"last_seen_at"`
	CreatedAt      int64    `json:"created_at"`
	GPUUtilPct     *int     `json:"gpu_util_pct,omitempty"`
	VRAMUsedGB     *float64 `json:"vram_used_gb,omitempty"`
	ActiveRequests *int     `json:"active_requests,omitempty"`
}

// EdgeHW + EdgeLoc are the agent-written / supplier-declared metadata.
//
// JSON tags MUST match backend/pkg/edge.{Hardware,Location} exactly.
// The backend's Location is shared between the HTTP DTO and the WS
// protocol the agent uses, so a tag rename here without a coordinated
// backend change will silently drop fields on the wire. Same applies
// to Hardware: missing fields here decode to zero values silently,
// and the CLI / MCP renderers can't surface what they didn't decode.
type EdgeHW struct {
	GPUModel    string `json:"gpu_model,omitempty"`
	GPUCount    int    `json:"gpu_count,omitempty"`
	VRAMTotalGB int    `json:"vram_total_gb,omitempty"`
	CUDAVersion string `json:"cuda_version,omitempty"`
	Driver      string `json:"driver,omitempty"`
	CPUModel    string `json:"cpu_model,omitempty"`
	RAMTotalGB  int    `json:"ram_total_gb,omitempty"`
	Platform    string `json:"platform,omitempty"`
}

type EdgeLoc struct {
	CountryISO2 string  `json:"country_iso2,omitempty"`
	Region      string  `json:"region,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
}

// EdgeNodeCreate is the request body for POST /api/seller/edge/nodes.
// AttachToChannelID is set when adding a sibling node to an existing
// edge channel (multi-node load balancing) — leave nil for a standalone
// node, which also auto-creates the paired Channel row server-side.
type EdgeNodeCreate struct {
	Name              string   `json:"name"`
	Location          *EdgeLoc `json:"location,omitempty"`
	AttachToChannelID *int     `json:"attach_to_channel_id,omitempty"`
	// Workloads is the capability declaration (chat / coding / image /
	// video / audio / render / embedding). Empty defaults to ["chat"]
	// server-side; unknown values are rejected with a 422.
	Workloads []string `json:"workloads,omitempty"`
}

// KnownEdgeWorkloads mirrors backend/pkg/edge.AllWorkloads — the
// closed set the backend accepts in EdgeNodeCreate.Workloads /
// EdgeNodeUpdate.Workloads. CLI front-ends validate against this list
// so a typo fails locally with the allowed values in the message
// instead of a terse server 422.
var KnownEdgeWorkloads = []string{
	"chat",
	"coding",
	"image",
	"video",
	"audio",
	"render",
	"embedding",
}

// EdgeNodeRegistration is the one-shot response after creating a node.
// RegistrationToken is shown EXACTLY once — the backend stores only its
// sha256 and clears that on first WS connect, so a CLI that loses the
// token has to delete the node and re-register. Persist it immediately
// to disk before returning to the user.
type EdgeNodeRegistration struct {
	Node              EdgeNode `json:"node"`
	RegistrationToken string   `json:"registration_token"`
}

// CreateEdgeNode wraps POST /api/seller/edge/nodes. Returns the node
// view + a single-use registration token. The token is what the agent
// presents on its first WS connect to claim the node row; it never
// reappears in any later response, so the caller MUST persist it
// before any other operation.
func (c *Client) CreateEdgeNode(ctx context.Context, req EdgeNodeCreate) (*EdgeNodeRegistration, error) {
	var env struct {
		Success bool                 `json:"success"`
		Message string               `json:"message"`
		Data    EdgeNodeRegistration `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/seller/edge/nodes", req, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// ListEdgeNodes wraps GET /api/seller/edge/nodes. Returns every node
// the caller owns regardless of status (offline / online / disabled);
// downstream callers filter by Status when rendering.
func (c *Client) ListEdgeNodes(ctx context.Context) ([]EdgeNode, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []EdgeNode `json:"items"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/seller/edge/nodes", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data.Items, nil
}

// GetEdgeNode wraps the implicit single-node read via the list filter.
// The backend doesn't ship a GET /:id endpoint (see api-router.go: only
// CRUD on the collection + status/logs subresources), so we filter the
// list locally. For a seller with one node this is a 1-row response,
// not worth a custom endpoint.
func (c *Client) GetEdgeNode(ctx context.Context, id int) (*EdgeNode, error) {
	nodes, err := c.ListEdgeNodes(ctx)
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		if nodes[i].ID == id {
			return &nodes[i], nil
		}
	}
	return nil, fmt.Errorf("edge node %d not found", id)
}

// EdgeNodeUpdate is the request body for PUT /api/seller/edge/nodes/:id.
// Name and Location are the only fields a seller may change here —
// hardware / models / agent_version are agent-reported and would be
// overwritten on the next reconnect, so the backend doesn't accept
// them in this payload. An empty Name leaves the existing name
// untouched, matching the backend's
// strings.TrimSpace+early-return behavior in UpdateEdgeNode.
type EdgeNodeUpdate struct {
	Name     string   `json:"name,omitempty"`
	Location *EdgeLoc `json:"location,omitempty"`
	// Workloads replaces the capability declaration when non-empty;
	// empty/omitted leaves the stored declaration untouched.
	Workloads []string `json:"workloads,omitempty"`
}

// UpdateEdgeNode wraps PUT /api/seller/edge/nodes/:id — the rename /
// edit-location surface. The backend also syncs the paired
// Channel.Name in the same transaction so the relay router's listing
// stays in lockstep with the dashboard's display.
func (c *Client) UpdateEdgeNode(ctx context.Context, id int, req EdgeNodeUpdate) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "PUT", fmt.Sprintf("/api/seller/edge/nodes/%d", id), req, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// DeleteEdgeNode wraps DELETE /api/seller/edge/nodes/:id. Cascade
// behaviour (drops the paired Channel + abilities only when this is
// the LAST node attached to that channel) is server-side; the CLI
// just calls the endpoint and renders the success/error message.
func (c *Client) DeleteEdgeNode(ctx context.Context, id int) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "DELETE", fmt.Sprintf("/api/seller/edge/nodes/%d", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// EdgeNodeAction is the closed enum the backend accepts on PATCH
// /api/seller/edge/nodes/:id/status. Exposed as named constants so
// callers can't accidentally pass "enabled" / "paused" / "stop" — the
// backend would silently reject those with "edge.invalid_action".
type EdgeNodeAction string

const (
	// EdgeNodeActionDisable flips the paired Channel to ManualDisabled
	// (sticky; the watchdog won't auto-resume it on the next heartbeat).
	EdgeNodeActionDisable EdgeNodeAction = "disable"
	// EdgeNodeActionEnable restores the paired Channel — sets it to
	// Enabled if the agent currently has a live session, else
	// AutoDisabled so the next reconnect's flip kicks it back on.
	EdgeNodeActionEnable EdgeNodeAction = "enable"
)

// SetEdgeNodeStatus wraps PATCH /api/seller/edge/nodes/:id/status.
// `action` MUST be one of EdgeNodeActionEnable / EdgeNodeActionDisable.
// Body shape and accepted values are dictated by backend
// edgehttp.SetEdgeNodeStatus (edgeNodeStatusRequest{Action}); the
// SDK is the consumer, not the source of truth.
func (c *Client) SetEdgeNodeStatus(ctx context.Context, id int, action EdgeNodeAction) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	req := struct {
		Action EdgeNodeAction `json:"action"`
	}{Action: action}
	if err := c.do(ctx, "PATCH", fmt.Sprintf("/api/seller/edge/nodes/%d/status", id), req, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

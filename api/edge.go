// Edge-node management surfaces — the seller-side endpoints under
// /api/seller/edge/nodes that the CLI's `everyapi edge ...` command
// group consumes. Shapes mirror backend/internal/controller/edge_node.go's
// edgeNodeView + edgeNodeCreateResponse but only decode what we render,
// so a future backend field addition doesn't break this client.
package api

import (
	"context"
	"fmt"
)

// EdgeNode is the seller-facing view of a registered BYO-GPU node.
// Status is the string form of pkg/edge.NodeStatus ("offline" /
// "online" / "disabled"); the dashboard and CLI both match on these
// strings, so renaming on the backend would break tooling.
type EdgeNode struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	ChannelID  *int      `json:"channel_id"`
	Paused     bool      `json:"paused"`
	Hardware   *EdgeHW   `json:"hardware,omitempty"`
	Location   *EdgeLoc  `json:"location,omitempty"`
	Models     []string  `json:"models,omitempty"`
	AgentVer   string    `json:"agent_version,omitempty"`
	LastSeenAt int64     `json:"last_seen_at"`
}

// EdgeHW + EdgeLoc are the agent-written / supplier-declared metadata.
// Kept loose (just the fields the CLI needs to render) — the backend
// pkg/edge.Hardware / pkg/edge.Location can grow without breaking us.
type EdgeHW struct {
	GPUModel string `json:"gpu_model,omitempty"`
	VRAMGB   int    `json:"vram_gb,omitempty"`
	GPUCount int    `json:"gpu_count,omitempty"`
}

type EdgeLoc struct {
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
}

// EdgeNodeCreate is the request body for POST /api/seller/edge/nodes.
// AttachToChannelID is set when adding a sibling node to an existing
// edge channel (multi-node load balancing) — leave nil for a standalone
// node, which also auto-creates the paired Channel row server-side.
type EdgeNodeCreate struct {
	Name              string   `json:"name"`
	Location          *EdgeLoc `json:"location,omitempty"`
	AttachToChannelID *int     `json:"attach_to_channel_id,omitempty"`
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
		return nil, fmt.Errorf("create edge node: %s", env.Message)
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
		return nil, fmt.Errorf("list edge nodes: %s", env.Message)
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
		return fmt.Errorf("delete edge node: %s", env.Message)
	}
	return nil
}

// SetEdgeNodeStatus wraps PATCH /api/seller/edge/nodes/:id/status.
// Server accepts "enabled" / "paused" — pausing flips the paired
// Channel to ManualDisabled (sticky; the auto-disable watchdog won't
// touch it), enabling flips it back to AutoDisabled and the next agent
// heartbeat picks the row up to Enabled.
func (c *Client) SetEdgeNodeStatus(ctx context.Context, id int, status string) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	req := struct {
		Status string `json:"status"`
	}{Status: status}
	if err := c.do(ctx, "PATCH", fmt.Sprintf("/api/seller/edge/nodes/%d/status", id), req, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("set edge node status: %s", env.Message)
	}
	return nil
}

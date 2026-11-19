package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// AdminChannel is the operator view of one upstream channel. It carries only non-secret columns: the admin list and detail endpoints never select the credential, and this type has no field to hold one.
type AdminChannel struct {
	ID            int     `json:"id"`
	Name          string  `json:"name"`
	KindSlug      string  `json:"kind_slug"`
	Status        int     `json:"status"`
	Models        string  `json:"models"`
	Group         string  `json:"group"`
	Tag           *string `json:"tag"`
	Priority      *int64  `json:"priority"`
	Weight        *uint   `json:"weight"`
	OwnerUserID   int     `json:"owner_user_id"`
	OwnerUsername string  `json:"owner_username"`
	OAuthEnabled  bool    `json:"oauth_enabled"`
	TestTime      int64   `json:"test_time"`
	ResponseTime  int     `json:"response_time"`
}

// ModelList splits the comma-separated models column the way the backend stores it, dropping blanks.
func (ch AdminChannel) ModelList() []string {
	var out []string
	for _, m := range strings.Split(ch.Models, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// AdminChannelFilter narrows AdminListChannels. Keyword and Model need the search endpoint; the plain list endpoint serves every other combination with server-side paging.
type AdminChannelFilter struct {
	Keyword  string
	Model    string
	Kind     string
	Group    string
	Status   string // "enabled", "disabled", or "" for all
	Page     int
	PageSize int
}

// AdminListChannels pages /api/channel, or /api/channel/search when Keyword or Model is set. Returns the page and the total match count.
func (c *Client) AdminListChannels(ctx context.Context, f AdminChannelFilter) ([]AdminChannel, int, error) {
	v := url.Values{}
	path := "/api/channel"
	if f.Keyword != "" || f.Model != "" {
		path = "/api/channel/search"
		if f.Keyword != "" {
			v.Set("keyword", f.Keyword)
		}
		if f.Model != "" {
			v.Set("model", f.Model)
		}
	}
	if f.Kind != "" {
		v.Set("kind", f.Kind)
	}
	if f.Group != "" {
		v.Set("group", f.Group)
	}
	if f.Status != "" {
		v.Set("status", f.Status)
	}
	if f.Page > 0 {
		v.Set("p", strconv.Itoa(f.Page))
	}
	if f.PageSize > 0 {
		v.Set("page_size", strconv.Itoa(f.PageSize))
	}
	if e := v.Encode(); e != "" {
		path += "?" + e
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []AdminChannel `json:"items"`
			Total int            `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", path, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// AdminGetChannel reads one channel from /api/channel/:id.
func (c *Client) AdminGetChannel(ctx context.Context, id int) (*AdminChannel, error) {
	if id <= 0 {
		return nil, fmt.Errorf("admin get channel: invalid id %d", id)
	}
	var env struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Data    *AdminChannel `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/channel/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	if env.Data == nil {
		return nil, fmt.Errorf("admin get channel: channel %d not found", id)
	}
	return env.Data, nil
}

// AdminAddChannelModels appends models to every listed channel through /api/channel/batch/models. The backend merges and de-duplicates, so re-adding a model a channel already serves is a no-op.
func (c *Client) AdminAddChannelModels(ctx context.Context, ids []int, models []string) error {
	if len(ids) == 0 || len(models) == 0 {
		return errors.New("admin add channel models: ids and models are required")
	}
	body := map[string]any{"ids": ids, "models": strings.Join(models, ",")}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/channel/batch/models", body, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// AdminSetChannelModels replaces one channel's model list through PUT /api/channel, sending only id and models so no other column is touched. The backend skips empty strings on this path, so an empty list is refused here rather than silently ignored there.
func (c *Client) AdminSetChannelModels(ctx context.Context, id int, models []string) (*AdminChannel, error) {
	if id <= 0 {
		return nil, fmt.Errorf("admin set channel models: invalid id %d", id)
	}
	if len(models) == 0 {
		return nil, errors.New("admin set channel models: a channel must keep at least one model")
	}
	body := map[string]any{"id": id, "models": strings.Join(models, ",")}
	var env struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Data    *AdminChannel `json:"data"`
	}
	if err := c.do(ctx, "PUT", "/api/channel", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

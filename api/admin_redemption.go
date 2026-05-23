// Admin redemption-code SDK: CRUD over /api/redemption (AdminAuth).
// Redemption codes are prepaid quota vouchers — `AddRedemption`
// MINTS quota, so creation is the one verb a CLI must surface
// carefully (it's the only place the generated key strings are
// returned). Mirrors admin.go's (rows, total, err) pagination shape.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// RedemptionStatus* mirror common.RedemptionCodeStatus* on the backend.
const (
	RedemptionStatusEnabled  = 1
	RedemptionStatusDisabled = 2
	RedemptionStatusUsed     = 3
)

// Redemption is one row from /api/redemption. Key is the 32-char
// voucher code. ExpiredTime is unix seconds; 0 means never expires.
// CreatorUsername / UsedUsername are display-only joins.
type Redemption struct {
	ID              int    `json:"id"`
	UserID          int    `json:"user_id"`
	Key             string `json:"key"`
	Status          int    `json:"status"`
	Name            string `json:"name"`
	Quota           int    `json:"quota"`
	CreatedTime     int64  `json:"created_time"`
	RedeemedTime    int64  `json:"redeemed_time"`
	ExpiredTime     int64  `json:"expired_time"`
	UsedUserID      int    `json:"used_user_id"`
	CreatorUsername string `json:"creator_username"`
	UsedUsername    string `json:"used_username"`
}

func redemptionPageQS(page, pageSize int) string {
	v := url.Values{}
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	if e := v.Encode(); e != "" {
		return "?" + e
	}
	return ""
}

// redemptionListEnv is the paged-list envelope shared by list + search.
type redemptionListEnv struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Items []Redemption `json:"items"`
		Total int          `json:"total"`
	} `json:"data"`
}

// AdminListRedemptions pages GET /api/redemption/. Admin-only.
func (c *Client) AdminListRedemptions(ctx context.Context, page, pageSize int) ([]Redemption, int, error) {
	var env redemptionListEnv
	if err := c.do(ctx, "GET", "/api/redemption/"+redemptionPageQS(page, pageSize), nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// AdminSearchRedemptions hits GET /api/redemption/search?keyword=…
func (c *Client) AdminSearchRedemptions(ctx context.Context, keyword string, page, pageSize int) ([]Redemption, int, error) {
	if keyword == "" {
		return nil, 0, fmt.Errorf("redemption search: empty keyword")
	}
	v := url.Values{}
	v.Set("keyword", keyword)
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	var env redemptionListEnv
	if err := c.do(ctx, "GET", "/api/redemption/search?"+v.Encode(), nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, errors.New(env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// AdminGetRedemption fetches one row by id.
func (c *Client) AdminGetRedemption(ctx context.Context, id int) (*Redemption, error) {
	if id <= 0 {
		return nil, fmt.Errorf("get redemption: invalid id %d", id)
	}
	var env struct {
		Success bool       `json:"success"`
		Message string     `json:"message"`
		Data    Redemption `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/redemption/%d", id), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// RedemptionCreateRequest is the POST /api/redemption/ body. Count is
// how many codes to mint (1–100); each gets Quota. ExpiredTime is unix
// seconds, 0 = never (must be in the future when non-zero).
type RedemptionCreateRequest struct {
	Name        string `json:"name"`
	Count       int    `json:"count"`
	Quota       int    `json:"quota"`
	ExpiredTime int64  `json:"expired_time,omitempty"`
}

// AdminCreateRedemptions mints Count codes and returns the generated
// key strings — the ONLY place the plaintext keys are returned, so the
// caller must capture them immediately. The backend has no transaction
// around the batch: on a mid-batch failure it returns success:false
// with the keys created so far, which surfaces here as an error (the
// partial keys are lost to the CLI — re-list to recover them).
func (c *Client) AdminCreateRedemptions(ctx context.Context, req RedemptionCreateRequest) ([]string, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("create redemption: empty name")
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	var env struct {
		Success bool     `json:"success"`
		Message string   `json:"message"`
		Data    []string `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/redemption/", req, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

// AdminUpdateRedemption edits name / quota / expired_time of one code
// (id required). Status is left untouched — use AdminSetRedemptionStatus.
func (c *Client) AdminUpdateRedemption(ctx context.Context, r Redemption) error {
	if r.ID <= 0 {
		return fmt.Errorf("update redemption: invalid id %d", r.ID)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "PUT", "/api/redemption/", r, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// AdminSetRedemptionStatus flips only the status via the status_only
// fast-path (PUT /api/redemption/?status_only=1).
func (c *Client) AdminSetRedemptionStatus(ctx context.Context, id, status int) error {
	if id <= 0 {
		return fmt.Errorf("set redemption status: invalid id %d", id)
	}
	body := Redemption{ID: id, Status: status}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "PUT", "/api/redemption/?status_only=1", body, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// AdminDeleteRedemption soft-deletes one code by id. Destructive.
func (c *Client) AdminDeleteRedemption(ctx context.Context, id int) error {
	if id <= 0 {
		return fmt.Errorf("delete redemption: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "DELETE", fmt.Sprintf("/api/redemption/%d", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// AdminDeleteInvalidRedemptions bulk-deletes every used / disabled /
// expired code and returns the number removed. Destructive and
// unconfirmed server-side — the caller should confirm first.
func (c *Client) AdminDeleteInvalidRedemptions(ctx context.Context) (int64, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}
	if err := c.do(ctx, "DELETE", "/api/redemption/invalid", nil, &env); err != nil {
		return 0, err
	}
	if !env.Success {
		return 0, errors.New(env.Message)
	}
	return env.Data, nil
}

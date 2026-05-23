// Notification-settings SDK: read / write the user's quota-warning
// notification channel (PUT /api/user/setting, POST /api/user/setting/test).
//
// IMPORTANT: the backend rebuilds the whole UserSetting blob on each
// PUT, so this endpoint must be paired with the backend fix that
// inherits the non-notify fields (sidebar / language / seller-mode /
// marketplace opt-in) from the stored setting — otherwise saving a
// channel wipes them. See the matching backend change.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// NotifySettingView is the notification subset parsed out of the user's
// setting blob (GetSelf's "setting" field). Empty NotifyType means no
// channel has been configured yet.
type NotifySettingView struct {
	NotifyType            string  `json:"notify_type"`
	QuotaWarningThreshold float64 `json:"quota_warning_threshold"`
	WebhookURL            string  `json:"webhook_url"`
	NotificationEmail     string  `json:"notification_email"`
	BarkURL               string  `json:"bark_url"`
	GotifyURL             string  `json:"gotify_url"`
	GotifyToken           string  `json:"gotify_token"`
	GotifyPriority        int     `json:"gotify_priority"`
}

// GetNotifySetting reads the current notification config by parsing the
// "setting" blob returned by GET /api/user/self. A malformed blob
// yields a zero-value view rather than an error — the CLI renders that
// as "not configured".
func (c *Client) GetNotifySetting(ctx context.Context) (*NotifySettingView, error) {
	self, err := c.GetSelf(ctx)
	if err != nil {
		return nil, err
	}
	view := &NotifySettingView{}
	if self.Setting != "" {
		_ = json.Unmarshal([]byte(self.Setting), view)
	}
	return view, nil
}

// NotifySettingRequest is the PUT /api/user/setting body. NotifyType is
// the channel (email/webhook/bark/gotify); the backend requires
// QuotaWarningThreshold > 0 on every write. Only the fields for the
// chosen channel need to be set — the backend ignores the rest.
type NotifySettingRequest struct {
	NotifyType            string  `json:"notify_type"`
	QuotaWarningThreshold float64 `json:"quota_warning_threshold"`
	WebhookURL            string  `json:"webhook_url,omitempty"`
	WebhookSecret         string  `json:"webhook_secret,omitempty"`
	NotificationEmail     string  `json:"notification_email,omitempty"`
	BarkURL               string  `json:"bark_url,omitempty"`
	GotifyURL             string  `json:"gotify_url,omitempty"`
	GotifyToken           string  `json:"gotify_token,omitempty"`
	GotifyPriority        int     `json:"gotify_priority,omitempty"`
}

// UpdateNotifySetting issues PUT /api/user/setting.
func (c *Client) UpdateNotifySetting(ctx context.Context, req NotifySettingRequest) error {
	if req.NotifyType == "" {
		return fmt.Errorf("notify setting: empty notify type")
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "PUT", "/api/user/setting", req, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// TestNotification fires a one-shot test message through the configured
// channel (POST /api/user/setting/test). The backend surfaces a
// delivery error verbatim, so a failed channel config shows up here.
func (c *Client) TestNotification(ctx context.Context) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/user/setting/test", nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

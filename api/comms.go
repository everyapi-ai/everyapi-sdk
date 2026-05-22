package api

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// --- notification ---------------------------------------------------

// Notification is one row from /api/notification. The body fields
// vary by notification type (compensation_filed / channel_disabled /
// dm_opened / …) so Payload stays opaque.
type Notification struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Payload   string `json:"payload"`
	ReadAt    int64  `json:"read_at"`
	CreatedAt int64  `json:"created_at"`
}

// ListNotifications pages /api/notification. unreadOnly maps to the
// ?unread=1 server-side filter — saves clients from re-filtering
// pages of read rows just to find the new ones.
func (c *Client) ListNotifications(ctx context.Context, unreadOnly bool, page, pageSize int) ([]Notification, int, error) {
	v := url.Values{}
	if unreadOnly {
		v.Set("unread", "1")
	}
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []Notification `json:"items"`
			Total int            `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/notification"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, fmt.Errorf("list notifications: %s", env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// NotificationUnreadCount returns the scalar /unread-count.
func (c *Client) NotificationUnreadCount(ctx context.Context) (int, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Unread int `json:"unread"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/notification/unread-count", nil, &env); err != nil {
		return 0, err
	}
	if !env.Success {
		return 0, fmt.Errorf("unread count: %s", env.Message)
	}
	return env.Data.Unread, nil
}

// MarkNotificationRead flips one row to read.
func (c *Client) MarkNotificationRead(ctx context.Context, id int) error {
	if id <= 0 {
		return fmt.Errorf("mark read: invalid id %d", id)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", fmt.Sprintf("/api/notification/%d/read", id), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("mark read: %s", env.Message)
	}
	return nil
}

// MarkAllNotificationsRead flips every unread row. Returns the
// number actually flipped — useful so the CLI can render "0 new"
// without a follow-up unread-count call.
func (c *Client) MarkAllNotificationsRead(ctx context.Context) (int, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Flipped int `json:"flipped"`
		} `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/notification/read-all", nil, &env); err != nil {
		return 0, err
	}
	if !env.Success {
		return 0, fmt.Errorf("mark all read: %s", env.Message)
	}
	return env.Data.Flipped, nil
}

// --- DM (direct messages) -------------------------------------------

// DMContact is one row from /api/dm/contacts.
type DMContact struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
}

// DMThread is one row from /api/dm/thread.
type DMThread struct {
	ID                 int    `json:"id"`
	OpenedAt           int64  `json:"opened_at"`
	LastMessageAt      int64  `json:"last_message_at"`
	LastMessagePreview string `json:"last_message_preview"`
	UnreadCount        int    `json:"unread_count"`
	OtherUserID        int    `json:"other_user_id"`
	OtherUsername      string `json:"other_username"`
}

// DMMessage is one message in a thread.
type DMMessage struct {
	ID         int    `json:"id"`
	ThreadID   int    `json:"thread_id"`
	SenderID   int    `json:"sender_id"`
	Body       string `json:"body"`
	CreatedAt  int64  `json:"created_at"`
	ReadAt     int64  `json:"read_at"`
}

// DMUnreadCount is the scalar from /api/dm/unread-count.
func (c *Client) DMUnreadCount(ctx context.Context) (int, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Unread int `json:"unread"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/dm/unread-count", nil, &env); err != nil {
		return 0, err
	}
	if !env.Success {
		return 0, fmt.Errorf("dm unread count: %s", env.Message)
	}
	return env.Data.Unread, nil
}

// ListDMContacts lists users you've already messaged or vice-versa.
func (c *Client) ListDMContacts(ctx context.Context) ([]DMContact, error) {
	var env struct {
		Success bool        `json:"success"`
		Message string      `json:"message"`
		Data    []DMContact `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/dm/contacts", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("list contacts: %s", env.Message)
	}
	return env.Data, nil
}

// ListDMThreads pages the caller's DM threads.
func (c *Client) ListDMThreads(ctx context.Context, page, pageSize int) ([]DMThread, int, error) {
	v := url.Values{}
	if page > 0 {
		v.Set("p", strconv.Itoa(page))
	}
	if pageSize > 0 {
		v.Set("page_size", strconv.Itoa(pageSize))
	}
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Items []DMThread `json:"items"`
			Total int        `json:"total"`
		} `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/dm/thread"+qs, nil, &env); err != nil {
		return nil, 0, err
	}
	if !env.Success {
		return nil, 0, fmt.Errorf("list threads: %s", env.Message)
	}
	return env.Data.Items, env.Data.Total, nil
}

// OpenDMThread starts a DM with another user (or returns the
// existing thread id). Idempotent server-side.
func (c *Client) OpenDMThread(ctx context.Context, otherUserID int) (*DMThread, error) {
	if otherUserID <= 0 {
		return nil, fmt.Errorf("open thread: invalid user id %d", otherUserID)
	}
	var env struct {
		Success bool     `json:"success"`
		Message string   `json:"message"`
		Data    DMThread `json:"data"`
	}
	body := struct {
		OtherUserID int `json:"other_user_id"`
	}{OtherUserID: otherUserID}
	if err := c.do(ctx, "POST", "/api/dm/thread", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("open thread: %s", env.Message)
	}
	return &env.Data, nil
}

// ListDMMessages reads messages from a thread. after is exclusive
// (id > after) so callers can poll incrementally without dedup.
func (c *Client) ListDMMessages(ctx context.Context, threadID, after, limit int) ([]DMMessage, error) {
	if threadID <= 0 {
		return nil, fmt.Errorf("list messages: invalid thread id %d", threadID)
	}
	v := url.Values{}
	if after > 0 {
		v.Set("after", strconv.Itoa(after))
	}
	if limit > 0 {
		v.Set("limit", strconv.Itoa(limit))
	}
	qs := ""
	if e := v.Encode(); e != "" {
		qs = "?" + e
	}
	var env struct {
		Success bool        `json:"success"`
		Message string      `json:"message"`
		Data    []DMMessage `json:"data"`
	}
	if err := c.do(ctx, "GET", fmt.Sprintf("/api/dm/thread/%d/messages%s", threadID, qs), nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("list messages: %s", env.Message)
	}
	return env.Data, nil
}

// SendDMMessage posts a message to a thread.
func (c *Client) SendDMMessage(ctx context.Context, threadID int, body string) (*DMMessage, error) {
	if threadID <= 0 {
		return nil, fmt.Errorf("send: invalid thread id %d", threadID)
	}
	if body == "" {
		return nil, fmt.Errorf("send: empty body")
	}
	var env struct {
		Success bool      `json:"success"`
		Message string    `json:"message"`
		Data    DMMessage `json:"data"`
	}
	req := struct {
		Body string `json:"body"`
	}{Body: body}
	if err := c.do(ctx, "POST", fmt.Sprintf("/api/dm/thread/%d/messages", threadID), req, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("send: %s", env.Message)
	}
	return &env.Data, nil
}

// MarkDMRead marks all messages in a thread as read (server-side
// updates the per-user read pointer).
func (c *Client) MarkDMRead(ctx context.Context, threadID int) error {
	if threadID <= 0 {
		return fmt.Errorf("mark read: invalid thread id %d", threadID)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", fmt.Sprintf("/api/dm/thread/%d/read", threadID), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("mark read: %s", env.Message)
	}
	return nil
}

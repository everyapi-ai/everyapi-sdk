// User-profile SDK additions: 2FA status / disable / backup-codes,
// passkey status, OAuth bindings list/unbind, affiliate code.
// These are the read-write surface a buyer needs from the terminal
// without bouncing through the dashboard.
//
// PasskeyStatus / PasskeyDelete are session-cookie auth on the
// backend; the bearer-token path may 401. SDK exposes both so the
// CLI can surface a clear "use the dashboard" message rather than
// silently hiding the feature.
package api

import (
	"context"
	"errors"
	"fmt"
)

// TwoFAStatus mirrors the {enabled, locked, backup_codes_remaining}
// shape Get2FAStatus emits. backup_codes_remaining is only present
// when enabled.
type TwoFAStatus struct {
	Enabled              bool `json:"enabled"`
	Locked               bool `json:"locked"`
	BackupCodesRemaining int  `json:"backup_codes_remaining"`
}

// Get2FAStatus reads /api/user/2fa/status.
func (c *Client) Get2FAStatus(ctx context.Context) (*TwoFAStatus, error) {
	var env struct {
		Success bool        `json:"success"`
		Message string      `json:"message"`
		Data    TwoFAStatus `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/2fa/status", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("2fa status: %s", env.Message)
	}
	return &env.Data, nil
}

// Disable2FA posts a TOTP or backup code and turns 2FA off.
func (c *Client) Disable2FA(ctx context.Context, code string) error {
	if code == "" {
		return fmt.Errorf("disable 2fa: empty code")
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	body := struct {
		Code string `json:"code"`
	}{Code: code}
	if err := c.do(ctx, "POST", "/api/user/2fa/disable", body, &env); err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("disable 2fa: %s", env.Message)
	}
	return nil
}

// RegenerateBackupCodes invalidates the old set and returns the new
// codes. Backend gates this on a fresh TOTP verification.
func (c *Client) RegenerateBackupCodes(ctx context.Context, code string) ([]string, error) {
	if code == "" {
		return nil, fmt.Errorf("regenerate backup codes: empty code")
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			BackupCodes []string `json:"backup_codes"`
		} `json:"data"`
	}
	body := struct {
		Code string `json:"code"`
	}{Code: code}
	if err := c.do(ctx, "POST", "/api/user/2fa/backup_codes", body, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data.BackupCodes, nil
}

// Setup2FAResult is the POST /api/user/2fa/setup payload: a fresh
// TOTP secret, the otpauth:// provisioning URI (render as a QR or
// type the secret into an authenticator), and one-time backup codes.
// Setup persists a DISABLED 2FA row — call Enable2FA with a TOTP code
// to turn it on. Backup codes are returned in cleartext only here.
type Setup2FAResult struct {
	Secret      string   `json:"secret"`
	QRCodeData  string   `json:"qr_code_data"`
	BackupCodes []string `json:"backup_codes"`
}

// Setup2FA begins 2FA enrollment (POST /api/user/2fa/setup). Fails
// with success:false if 2FA is already enabled. Pair with Enable2FA.
func (c *Client) Setup2FA(ctx context.Context) (*Setup2FAResult, error) {
	var env struct {
		Success bool           `json:"success"`
		Message string         `json:"message"`
		Data    Setup2FAResult `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/user/2fa/setup", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// Enable2FA finishes enrollment with the 6-digit TOTP code from the
// authenticator (POST /api/user/2fa/enable). The secret was already
// persisted by Setup2FA, so only the code is sent. Backup codes are
// NOT accepted here.
func (c *Client) Enable2FA(ctx context.Context, code string) error {
	if code == "" {
		return fmt.Errorf("enable 2fa: empty code")
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	body := struct {
		Code string `json:"code"`
	}{Code: code}
	if err := c.do(ctx, "POST", "/api/user/2fa/enable", body, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// PasskeyStatus is the {enabled, last_used_at} payload PasskeyStatus
// emits when a passkey is registered; last_used_at is zero when not.
type PasskeyStatus struct {
	Enabled    bool  `json:"enabled"`
	LastUsedAt int64 `json:"last_used_at"`
}

// GetPasskeyStatus reads /api/user/passkey. May 401 over bearer
// auth on backends that gate this endpoint on the dashboard session
// cookie — caller should handle IsUnauthorized gracefully.
func (c *Client) GetPasskeyStatus(ctx context.Context) (*PasskeyStatus, error) {
	var env struct {
		Success bool          `json:"success"`
		Message string        `json:"message"`
		Data    PasskeyStatus `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/passkey", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return &env.Data, nil
}

// OAuthBinding is one row from /api/user/oauth/bindings. ProviderSlug
// is the human-friendly id used in routes (/api/oauth/:provider).
type OAuthBinding struct {
	ProviderID     int    `json:"provider_id"`
	ProviderName   string `json:"provider_name"`
	ProviderSlug   string `json:"provider_slug"`
	ProviderIcon   string `json:"provider_icon"`
	ProviderUserID string `json:"provider_user_id"`
}

// ListOAuthBindings reads /api/user/oauth/bindings.
func (c *Client) ListOAuthBindings(ctx context.Context) ([]OAuthBinding, error) {
	var env struct {
		Success bool           `json:"success"`
		Message string         `json:"message"`
		Data    []OAuthBinding `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/oauth/bindings", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, errors.New(env.Message)
	}
	return env.Data, nil
}

// UnbindOAuth removes one OAuth binding by provider id.
func (c *Client) UnbindOAuth(ctx context.Context, providerID int) error {
	if providerID <= 0 {
		return fmt.Errorf("unbind oauth: invalid provider id %d", providerID)
	}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "DELETE", fmt.Sprintf("/api/user/oauth/bindings/%d", providerID), nil, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// GetAffCode reads /api/user/aff. Backend lazy-generates the code
// on first call; subsequent calls return the same code.
func (c *Client) GetAffCode(ctx context.Context) (string, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    string `json:"data"`
	}
	if err := c.do(ctx, "GET", "/api/user/aff", nil, &env); err != nil {
		return "", err
	}
	if !env.Success {
		return "", errors.New(env.Message)
	}
	return env.Data, nil
}

// ResetAffCode rotates the affiliate code. Old links that embedded
// the previous code stop crediting this inviter.
func (c *Client) ResetAffCode(ctx context.Context) (string, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    string `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/user/aff/reset", nil, &env); err != nil {
		return "", err
	}
	if !env.Success {
		return "", errors.New(env.Message)
	}
	return env.Data, nil
}

// TransferAffQuota moves `quota` units from the affiliate-reward balance
// into the caller's main Quota (POST /api/user/aff_transfer) — the
// affiliate-side mirror of TransferSellerQuota. A backend-formatted 4xx
// (insufficient affiliate balance, etc.) surfaces via the *APIError path.
func (c *Client) TransferAffQuota(ctx context.Context, quota int) error {
	if quota <= 0 {
		return fmt.Errorf("quota must be positive, got %d", quota)
	}
	body := map[string]int{"quota": quota}
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/user/aff_transfer", body, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

// UpdateProfileRequest carries the fields PUT /api/user/self honors in
// its generic-update branch (username / display_name / password). Empty
// fields are omitted so a partial update preserves the rest. Changing
// the password requires OriginalPassword — the backend verifies it
// against the stored hash and rejects a mismatch. Do NOT set the
// setting-only keys (sidebar_modules / language / seller_mode_on /
// marketplace_opt_in) here: PUT /api/user/self dispatches on the first
// matching key, so any of those would short-circuit before the profile
// branch ever runs.
type UpdateProfileRequest struct {
	Username         string `json:"username,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	Password         string `json:"password,omitempty"`
	OriginalPassword string `json:"original_password,omitempty"`
}

// UpdateProfile issues PUT /api/user/self for the generic profile
// branch. The user can only ever update themselves — the backend forces
// the id from the session and ignores quota/role/group/email in the
// body.
func (c *Client) UpdateProfile(ctx context.Context, req UpdateProfileRequest) error {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "PUT", "/api/user/self", req, &env); err != nil {
		return err
	}
	if !env.Success {
		return errors.New(env.Message)
	}
	return nil
}

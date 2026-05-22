// CLI jump-session client — the anti-phishing handshake from
// EVERYAPI §7-5 Layer 3. The CLI / menubar gets back a
// {session_id, phrase} pair, prints the phrase to the terminal,
// asks the user to confirm, and only then opens the browser to a
// URL it composes itself using its own knowledge of dashboard
// routes. The dashboard page reads ?jump_session=<id> on arrival
// and fetches + displays the same phrase, so the user's visual
// compare confirms the page is reachable from the same backend
// that minted the session.
package api

import (
	"context"
	"fmt"
)

// JumpSessionResult is the start-side payload. VerificationPhrase
// is the emoji string the user should see ALSO displayed at the
// top of the dashboard page once the CLI opens the browser.
// ExpiresIn is for the CLI to render a "this expires in N seconds"
// hint. The dashboard URL is NOT in the response — the caller
// composes it (the backend has no authoritative knowledge of
// frontend route names and shouldn't acquire one).
type JumpSessionResult struct {
	SessionID          string
	VerificationPhrase string
	ExpiresIn          int
}

// CreateJumpSession mints a jump session. The backend doesn't
// take any input beyond the auth header — it just mints a
// session id, a verification phrase, and returns them. Callers
// build the dashboard URL with WebOriginFromBase() + their own
// path + "?jump_session=" + SessionID.
func (c *Client) CreateJumpSession(ctx context.Context) (*JumpSessionResult, error) {
	var env struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			SessionID          string `json:"session_id"`
			VerificationPhrase string `json:"verification_phrase"`
			ExpiresIn          int    `json:"expires_in"`
		} `json:"data"`
	}
	if err := c.do(ctx, "POST", "/api/cli/jump-session", nil, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("create jump session: %s", env.Message)
	}
	return &JumpSessionResult{
		SessionID:          env.Data.SessionID,
		VerificationPhrase: env.Data.VerificationPhrase,
		ExpiresIn:          env.Data.ExpiresIn,
	}, nil
}

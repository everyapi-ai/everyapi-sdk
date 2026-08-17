package api

import (
	"context"
	"errors"
)

// --- user feedback ----------------------------------------------------

// FeedbackKind is the report category POST /api/user/feedback accepts. The server rejects anything outside this set, so callers should offer exactly these.
type FeedbackKind string

const (
	FeedbackKindBug     FeedbackKind = "bug"
	FeedbackKindFeature FeedbackKind = "feature"
	FeedbackKindOther   FeedbackKind = "other"
)

// FeedbackKinds lists every accepted category in the order a picker should show them.
var FeedbackKinds = []FeedbackKind{FeedbackKindBug, FeedbackKindFeature, FeedbackKindOther}

// Valid reports whether k is a category the server will accept.
func (k FeedbackKind) Valid() bool {
	for _, known := range FeedbackKinds {
		if k == known {
			return true
		}
	}
	return false
}

// Server-side field limits, counted in Unicode code points. Mirrored here so a client can stop the user at the boundary instead of round-tripping a rejection; the server remains the authority.
const (
	FeedbackContentMax = 2000
	FeedbackContactMax = 200
)

// FeedbackSubmit is the POST /api/user/feedback payload. Authenticated endpoint (UserAuth): the report carries the caller's identity so the operator can follow up.
type FeedbackSubmit struct {
	Kind FeedbackKind `json:"kind"`
	// Content is the report body as typed by the user. The only multi-line field.
	Content string `json:"content"`
	// Contact is an optional way to reach the submitter other than their account email.
	Contact string `json:"contact,omitempty"`
	// PageURL is where the user was when they filed it. Triage context only; a desktop client should send the surface it was opened from.
	PageURL string `json:"page_url,omitempty"`
}

// Stable failure codes the feedback endpoint answers with, alongside its human-readable message. A GUI that cannot show server text — EveryAPI Connect's renderer is handed codes, never sidecar output — localizes off these instead.
const (
	FeedbackCodeInvalidKind    = "invalid_kind"
	FeedbackCodeContentEmpty   = "content_empty"
	FeedbackCodeContentTooLong = "content_too_long"
	FeedbackCodeContactTooLong = "contact_too_long"
	FeedbackCodeRateLimited    = "rate_limited"
	FeedbackCodeUnavailable    = "unavailable"
	FeedbackCodeDeliveryFailed = "delivery_failed"
)

// FeedbackError is a refusal from the feedback endpoint. Code is stable and safe to branch on; Message is the server's own localized sentence, rendered in the account's language.
type FeedbackError struct {
	Code    string
	Message string
}

func (e *FeedbackError) Error() string { return e.Message }

// SubmitFeedback files one bug report / feature request. It is relayed straight to the operator's chat and nothing persists it, so the send is synchronous and a returned error means the report reached nobody — surface it and keep the user's draft rather than reporting success. A refusal from the endpoint comes back as *FeedbackError; a transport failure comes back as whatever the client produced.
func (c *Client) SubmitFeedback(ctx context.Context, req FeedbackSubmit) error {
	var env struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/user/feedback", req, &env); err != nil {
		return err
	}
	if !env.Success {
		message := env.Message
		if message == "" {
			// An older backend, or a path that answers without copy. Never return an error whose text is empty — the CLI prints it verbatim.
			message = "feedback was not accepted"
		}
		return &FeedbackError{Code: env.Code, Message: message}
	}
	return nil
}

// FeedbackErrorCode returns the stable code when err came from the feedback endpoint, or "" for a transport failure or any other error.
func FeedbackErrorCode(err error) string {
	var fe *FeedbackError
	if errors.As(err, &fe) {
		return fe.Code
	}
	return ""
}

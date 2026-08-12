package api

import (
	"context"
	"fmt"
	"net/http"
)

type DiagnosticMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type DiagnosticFinding struct {
	Section string `json:"section,omitempty"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

type DiagnosticChatRequest struct {
	TargetID    string              `json:"target_id"`
	Messages    []DiagnosticMessage `json:"messages"`
	Diagnostics []DiagnosticFinding `json:"diagnostics,omitempty"`
}

type DiagnosticChatResult struct {
	Message        string `json:"message"`
	Model          string `json:"model"`
	RemainingToday int    `json:"remaining_today"`
}

func (c *Client) DiagnosticChat(ctx context.Context, request DiagnosticChatRequest) (DiagnosticChatResult, error) {
	var envelope struct {
		Success bool                 `json:"success"`
		Message string               `json:"message"`
		Data    DiagnosticChatResult `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/desktop/diagnostics/chat", request, &envelope); err != nil {
		return DiagnosticChatResult{}, err
	}
	if !envelope.Success {
		return DiagnosticChatResult{}, fmt.Errorf("diagnostic chat rejected: %s", envelope.Message)
	}
	return envelope.Data, nil
}

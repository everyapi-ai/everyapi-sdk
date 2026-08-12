package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
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

type DiagnosticChatStreamError struct{ Code string }

func (e *DiagnosticChatStreamError) Error() string { return "diagnostic chat stream: " + e.Code }

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

func (c *Client) DiagnosticChatStream(ctx context.Context, request DiagnosticChatRequest, emit func(string) error) (DiagnosticChatResult, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return DiagnosticChatResult{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/desktop/diagnostics/chat/stream", bytes.NewReader(body))
	if err != nil {
		return DiagnosticChatResult{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/x-ndjson")
	if c.token != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.userID > 0 {
		httpRequest.Header.Set("EveryAPI-User-Id", strconv.Itoa(c.userID))
	}
	if lang := os.Getenv("EVERYAPI_LANG"); lang != "" {
		httpRequest.Header.Set("Accept-Language", lang)
	}
	response, err := c.doHTTP(httpRequest, c.hc)
	if err != nil {
		return DiagnosticChatResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, maxAPIResponseBytes+1))
		return DiagnosticChatResult{}, &APIError{StatusCode: response.StatusCode, Body: string(data)}
	}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, maxAPIResponseBytes+1))
	scanner.Buffer(make([]byte, 4*1024), 128*1024)
	var result DiagnosticChatResult
	done := false
	received := false
	totalBytes := 0
	for scanner.Scan() {
		var event struct {
			Version        int     `json:"version"`
			Type           string  `json:"type"`
			Delta          *string `json:"delta"`
			Model          *string `json:"model"`
			RemainingToday *int    `json:"remaining_today"`
			Code           *string `json:"code"`
		}
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil || event.Version != 2 {
			return DiagnosticChatResult{}, fmt.Errorf("invalid diagnostic stream")
		}
		switch event.Type {
		case "delta":
			if event.Delta == nil || *event.Delta == "" || event.Model != nil || event.RemainingToday != nil || event.Code != nil || done {
				return DiagnosticChatResult{}, fmt.Errorf("invalid diagnostic stream delta")
			}
			totalBytes += len(*event.Delta)
			if totalBytes > 8*1024 {
				return DiagnosticChatResult{}, fmt.Errorf("diagnostic stream reply too large")
			}
			received = true
			if err := emit(*event.Delta); err != nil {
				return DiagnosticChatResult{}, err
			}
		case "done":
			if done || !received || event.Delta != nil || event.Code != nil || event.Model == nil || *event.Model != "deepseek-v4-flash" || event.RemainingToday == nil || *event.RemainingToday < 0 || *event.RemainingToday > 20 {
				return DiagnosticChatResult{}, fmt.Errorf("invalid diagnostic stream completion")
			}
			done = true
			result.Model, result.RemainingToday = *event.Model, *event.RemainingToday
		case "error":
			if event.Delta != nil || event.Model != nil || event.RemainingToday != nil || event.Code == nil || (*event.Code != "invalid_request" && *event.Code != "daily_limit_reached" && *event.Code != "unavailable") {
				return DiagnosticChatResult{}, fmt.Errorf("invalid diagnostic stream error")
			}
			return DiagnosticChatResult{}, &DiagnosticChatStreamError{Code: *event.Code}
		default:
			return DiagnosticChatResult{}, fmt.Errorf("invalid diagnostic stream event")
		}
	}
	if err := scanner.Err(); err != nil {
		return DiagnosticChatResult{}, err
	}
	if !done {
		return DiagnosticChatResult{}, fmt.Errorf("truncated diagnostic stream")
	}
	return result, nil
}

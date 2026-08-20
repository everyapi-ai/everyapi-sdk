package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

const BenchmarkImportProtocolVersion = 1

type BenchmarkGrader string

const (
	BenchmarkGraderGo    BenchmarkGrader = "go test ./..."
	BenchmarkGraderCargo BenchmarkGrader = "cargo test --all-targets"
	BenchmarkGraderBun   BenchmarkGrader = "bun install --frozen-lockfile && bun test"
)

// BenchmarkRunUpload is deliberately content-free. Digests identify the clean
// repository tree and task while the patch, source, prompt, and agent output
// remain on the user's machine.
type BenchmarkRunUpload struct {
	RunID            string                  `json:"run_id"`
	RepositoryDigest string                  `json:"repository_digest"`
	TaskDigest       string                  `json:"task_digest"`
	Grader           BenchmarkGrader         `json:"grader"`
	Results          []BenchmarkResultUpload `json:"results"`
}

type BenchmarkResultUpload struct {
	Harness    string   `json:"harness"`
	Model      string   `json:"model"`
	Score      int      `json:"score"`
	CostUSD    *float64 `json:"cost_usd,omitempty"`
	DurationMS uint64   `json:"duration_ms"`
}

type BenchmarkImportReceipt struct {
	RunID           string `json:"run_id"`
	ImportedResults int    `json:"imported_results"`
	CreatedAt       int64  `json:"created_at"`
}

type BenchmarkImportError struct {
	Code    string
	Message string
}

func (e *BenchmarkImportError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

type benchmarkImportWire struct {
	Version          int                     `json:"version"`
	RunID            string                  `json:"run_id"`
	RepositoryDigest string                  `json:"repository_digest"`
	TaskDigest       string                  `json:"task_digest"`
	Grader           BenchmarkGrader         `json:"grader"`
	Results          []BenchmarkResultUpload `json:"results"`
	Signature        string                  `json:"signature"`
}

type benchmarkSigningPayload struct {
	Version          int                     `json:"version"`
	RunID            string                  `json:"run_id"`
	RepositoryDigest string                  `json:"repository_digest"`
	TaskDigest       string                  `json:"task_digest"`
	Grader           BenchmarkGrader         `json:"grader"`
	Results          []BenchmarkResultUpload `json:"results"`
}

func (c *Client) ImportBenchmarkRun(ctx context.Context, upload BenchmarkRunUpload) (*BenchmarkImportReceipt, error) {
	if c == nil || c.token == "" || c.userID <= 0 {
		return nil, errors.New("not signed in")
	}
	signature, err := benchmarkImportSignature(c.token, upload)
	if err != nil {
		return nil, err
	}
	wire := canonicalBenchmarkWire(upload)
	wire.Signature = signature
	var env struct {
		Success bool                    `json:"success"`
		Data    *BenchmarkImportReceipt `json:"data"`
		Code    string                  `json:"code"`
		Message string                  `json:"message"`
	}
	if err := c.do(ctx, "POST", "/api/user/quality/benchmark-runs", wire, &env); err != nil {
		return nil, err
	}
	if !env.Success || env.Data == nil {
		return nil, &BenchmarkImportError{Code: env.Code, Message: env.Message}
	}
	return env.Data, nil
}

func benchmarkImportSignature(token string, upload BenchmarkRunUpload) (string, error) {
	wire := canonicalBenchmarkWire(upload)
	payload := benchmarkSigningPayload{
		Version: wire.Version, RunID: wire.RunID,
		RepositoryDigest: wire.RepositoryDigest, TaskDigest: wire.TaskDigest,
		Grader: wire.Grader, Results: wire.Results,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(encoded)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func canonicalBenchmarkWire(upload BenchmarkRunUpload) benchmarkImportWire {
	results := append([]BenchmarkResultUpload(nil), upload.Results...)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Harness != results[j].Harness {
			return results[i].Harness < results[j].Harness
		}
		return results[i].Model < results[j].Model
	})
	return benchmarkImportWire{
		Version: BenchmarkImportProtocolVersion, RunID: upload.RunID,
		RepositoryDigest: upload.RepositoryDigest, TaskDigest: upload.TaskDigest,
		Grader: upload.Grader, Results: results,
	}
}

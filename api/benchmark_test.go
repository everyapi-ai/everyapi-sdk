package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func benchmarkUploadFixture() BenchmarkRunUpload {
	cost := 0.25
	return BenchmarkRunUpload{
		RunID:            "11111111-1111-4111-8111-111111111111",
		RepositoryDigest: strings.Repeat("a", 64),
		TaskDigest:       strings.Repeat("b", 64),
		Grader:           BenchmarkGraderGo,
		Results: []BenchmarkResultUpload{
			{Harness: "codex", Model: "gpt-5.6", Score: 100, CostUSD: &cost, DurationMS: 1000},
			{Harness: "claude", Model: "claude-sonnet", Score: 0, DurationMS: 2000},
		},
	}
}

func TestBenchmarkImportSignatureMatchesBackendVector(t *testing.T) {
	got, err := benchmarkImportSignature("vector-secret", benchmarkUploadFixture())
	if err != nil {
		t.Fatal(err)
	}
	const want = "dd396cb027e5e0e819d260a6974be702ec695b4a7cb8d05777c10ecae7257eff"
	if got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestImportBenchmarkRunSignsCanonicalPayloadAndReturnsReceipt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/user/quality/benchmark-runs" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer vector-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("EveryAPI-User-Id"); got != "42" {
			t.Fatalf("EveryAPI-User-Id = %q", got)
		}
		var body benchmarkImportWire
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Version != BenchmarkImportProtocolVersion || body.Signature != "dd396cb027e5e0e819d260a6974be702ec695b4a7cb8d05777c10ecae7257eff" {
			t.Fatalf("signed body = %#v", body)
		}
		if len(body.Results) != 2 || body.Results[0].Harness != "claude" || body.Results[1].Harness != "codex" {
			t.Fatalf("results were not canonicalized: %#v", body.Results)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"success":true,"data":{"run_id":"11111111-1111-4111-8111-111111111111","imported_results":2,"created_at":1770000000}}`))
	}))
	defer server.Close()

	receipt, err := New(server.URL, "vector-secret").WithUserID(42).
		ImportBenchmarkRun(context.Background(), benchmarkUploadFixture())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.RunID != benchmarkUploadFixture().RunID || receipt.ImportedResults != 2 || receipt.CreatedAt != 1770000000 {
		t.Fatalf("receipt = %#v", receipt)
	}
}

func TestImportBenchmarkRunRequiresCredentialAndSuccessEnvelope(t *testing.T) {
	if _, err := New("https://example.invalid", "").WithUserID(42).
		ImportBenchmarkRun(context.Background(), benchmarkUploadFixture()); err == nil {
		t.Fatal("expected missing credential to fail locally")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"code":"benchmark_conflict","message":"conflict"}`))
	}))
	defer server.Close()
	if _, err := New(server.URL, "token").WithUserID(42).
		ImportBenchmarkRun(context.Background(), benchmarkUploadFixture()); err == nil {
		t.Fatal("expected unsuccessful envelope to fail")
	}
}

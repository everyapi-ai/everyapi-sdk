package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientRejectsOversizedJSONResponse(t *testing.T) {
	srv := oversizedResponseServer(t)

	err := New(srv.URL, "").do(context.Background(), http.MethodGet, "/oversized", nil, &struct{}{})
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("error = %v, want response-size error", err)
	}
}

func TestOAuth2FormRejectsOversizedJSONResponse(t *testing.T) {
	srv := oversizedResponseServer(t)

	_, _, err := New(srv.URL, "").oauth2Form(context.Background(), "/oauth", url.Values{})
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("error = %v, want response-size error", err)
	}
}

func oversizedResponseServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.CopyN(w, zeroResponseReader{}, maxAPIResponseBytes+1)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type zeroResponseReader struct{}

func (zeroResponseReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

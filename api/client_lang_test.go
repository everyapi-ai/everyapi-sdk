package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAcceptLanguageHeader pins the EVERYAPI_LANG → Accept-Language
// header plumbing in client.do(). It's a global hook (set once at
// CLI startup, read by every request) so a regression that drops
// the os.Getenv lookup would silently un-translate every backend
// error message. Test catches that loudly.
func TestAcceptLanguageHeader(t *testing.T) {
	t.Run("EVERYAPI_LANG=zh sends Accept-Language: zh", func(t *testing.T) {
		t.Setenv("EVERYAPI_LANG", "zh")
		var seen string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Get("Accept-Language")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
		}))
		defer srv.Close()
		c := New(srv.URL, "tok").WithUserID(7)
		// Use a no-body GET via the un-exported do() — pick an
		// SDK method that performs one to exercise the path.
		// GetStatus is unauthenticated + zero-arg, perfect probe.
		_, _ = c.GetStatus(context.Background())
		if seen != "zh" {
			t.Errorf("Accept-Language = %q, want zh", seen)
		}
	})

	t.Run("EVERYAPI_LANG=zh-CN passes IETF tag through", func(t *testing.T) {
		// Backend's i18n.ParseAcceptLanguage prefix-matches "zh" so
		// "zh-CN" still routes correctly. Just confirm we don't
		// mangle it on the way out.
		t.Setenv("EVERYAPI_LANG", "zh-CN")
		var seen string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Get("Accept-Language")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
		}))
		defer srv.Close()
		c := New(srv.URL, "tok").WithUserID(7)
		_, _ = c.GetStatus(context.Background())
		if seen != "zh-CN" {
			t.Errorf("Accept-Language = %q, want zh-CN", seen)
		}
	})

	t.Run("EVERYAPI_LANG unset → no header (let backend default)", func(t *testing.T) {
		t.Setenv("EVERYAPI_LANG", "")
		gotHeader := true
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// http.Header.Get returns "" both for "header absent"
			// and "header set to empty string" — disambiguate via
			// Values, which only contains explicitly-set entries.
			if _, ok := r.Header["Accept-Language"]; !ok {
				gotHeader = false
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
		}))
		defer srv.Close()
		c := New(srv.URL, "tok").WithUserID(7)
		_, _ = c.GetStatus(context.Background())
		if gotHeader {
			t.Errorf("Accept-Language should be absent when EVERYAPI_LANG unset, but server saw it set")
		}
	})
}

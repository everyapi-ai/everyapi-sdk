package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpdateSellerChannel(t *testing.T) {
	t.Run("rejects invalid id locally", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("server should not be called for invalid id")
		}))
		defer srv.Close()
		err := New(srv.URL, "acc").WithUserID(7).UpdateSellerChannel(context.Background(), 0, SellerChannelUpdate{})
		if err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("happy path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "PUT" || r.URL.Path != "/api/seller/channel/42" {
				t.Errorf("got %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true}`))
		}))
		defer srv.Close()
		if err := New(srv.URL, "acc").WithUserID(7).UpdateSellerChannel(context.Background(), 42, SellerChannelUpdate{Name: "x", Status: ChannelStatusEnabled}); err != nil {
			t.Fatalf("UpdateSellerChannel: %v", err)
		}
	})
}

func TestDeleteSellerChannel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/api/seller/channel/42" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	if err := New(srv.URL, "acc").WithUserID(7).DeleteSellerChannel(context.Background(), 42); err != nil {
		t.Fatalf("DeleteSellerChannel: %v", err)
	}
}

func TestRefreshChannelCredential(t *testing.T) {
	t.Run("rejects unknown kind locally", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("server should not be called for unknown kind")
		}))
		defer srv.Close()
		_, err := New(srv.URL, "acc").WithUserID(7).RefreshChannelCredential(context.Background(), 1, "weirdkind")
		if err == nil || !strings.Contains(err.Error(), "unknown kind") {
			t.Errorf("want unknown-kind error, got %v", err)
		}
	})
	t.Run("happy path picks the right url", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/channel/9/claude/refresh" {
				t.Errorf("path = %q", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"channel_id":9,"channel_type":"claude","email":"u@x.com","expires_at":"2024-12-31T23:59:59Z","last_refresh":"2024-12-31T22:00:00Z"}}`))
		}))
		defer srv.Close()
		res, err := New(srv.URL, "acc").WithUserID(7).RefreshChannelCredential(context.Background(), 9, "claude")
		if err != nil {
			t.Fatalf("RefreshChannelCredential: %v", err)
		}
		if res.ChannelID != 9 || res.Email != "u@x.com" {
			t.Errorf("got %+v", res)
		}
		// Backend returns RFC3339 strings, not Unix ints — decoding them must
		// not error (the bug) and the values must round-trip.
		if res.ExpiresAt != "2024-12-31T23:59:59Z" || res.LastRefresh != "2024-12-31T22:00:00Z" {
			t.Errorf("RFC3339 timestamps not decoded: %+v", res)
		}
	})
}

func TestSubmitCompensationClaim(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/seller/compensation-claim" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"id":7,"status":"pending","suggested_cap":15000,"upstream_provider":"anthropic","description":"outage"}}`))
	}))
	defer srv.Close()
	row, err := New(srv.URL, "acc").WithUserID(7).SubmitCompensationClaim(context.Background(), CompensationClaimSubmit{
		UpstreamProvider: "anthropic", Description: "outage",
	})
	if err != nil {
		t.Fatalf("SubmitCompensationClaim: %v", err)
	}
	if row.ID != 7 || row.SuggestedCap != 15000 || row.Status != "pending" {
		t.Errorf("got %+v", row)
	}
}

func TestListCompensationClaims(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/seller/compensation-claims" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("status") != "pending" {
			t.Errorf("status arg lost: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"total":1,"items":[{"id":7,"status":"pending"}]}}`))
	}))
	defer srv.Close()
	items, total, err := New(srv.URL, "acc").WithUserID(7).ListCompensationClaims(context.Background(), "pending", 0, 0)
	if err != nil {
		t.Fatalf("ListCompensationClaims: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != 7 {
		t.Errorf("got items=%+v total=%d", items, total)
	}
}

func TestGetSellerSales(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/seller_sales" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"total":1,"items":[{"created_at":1700000000,"model_name":"gpt-4o","buyer_charge":100,"seller_take":80,"buyer_anon":"abc123def456"}]}}`))
	}))
	defer srv.Close()
	items, total, err := New(srv.URL, "acc").WithUserID(7).GetSellerSales(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("GetSellerSales: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].BuyerCharge != 100 {
		t.Errorf("got %+v", items)
	}
}

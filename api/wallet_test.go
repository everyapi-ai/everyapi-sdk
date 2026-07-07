package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetTopupInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/topup/info" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{
			"enable_fluxa_topup":true,
			"min_topup":10,"fluxa_min_topup":5,
			"pay_methods":[],
			"amount_options":[10,50,100],
			"discount":{"100":0.95},
			"topup_link":"https://dash/topup"
		}}`))
	}))
	defer srv.Close()
	info, err := New(srv.URL, "acc").WithUserID(7).GetTopupInfo(context.Background())
	if err != nil {
		t.Fatalf("GetTopupInfo: %v", err)
	}
	if !info.EnableFluxaTopup || info.FluxaMinTopup != 5 || info.MinTopup != 10 {
		t.Errorf("scalar fields: %+v", info)
	}
	if len(info.PayMethods) != 0 {
		t.Errorf("pay_methods: %+v", info.PayMethods)
	}
	if info.Discount["100"] != 0.95 {
		t.Errorf("discount: %v", info.Discount)
	}
}

func TestListUserTopups(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/user/topup/self" {
				t.Errorf("path = %q", r.URL.Path)
			}
			if r.URL.Query().Get("keyword") != "fluxa" {
				t.Errorf("keyword arg lost: %q", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":{"total":2,"items":[
				{"id":1,"amount":50,"money":10.5,"status":"done","payment_method":"fluxa","trade_no":"t-1","create_time":1700000000}
			]}}`))
		}))
		defer srv.Close()
		rows, total, err := New(srv.URL, "acc").WithUserID(7).ListUserTopups(context.Background(), 1, 20, "fluxa")
		if err != nil {
			t.Fatalf("ListUserTopups: %v", err)
		}
		if total != 2 || len(rows) != 1 || rows[0].PaymentMethod != "fluxa" {
			t.Errorf("got rows=%+v total=%d", rows, total)
		}
	})

	t.Run("no args means no querystring", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "" {
				t.Errorf("zero args should not produce a querystring, got %q", r.URL.RawQuery)
			}
			w.Write([]byte(`{"success":true,"data":{"total":0,"items":[]}}`))
		}))
		defer srv.Close()
		_, _, _ = New(srv.URL, "acc").WithUserID(7).ListUserTopups(context.Background(), 0, 0, "")
	})
}

func TestRedeem(t *testing.T) {
	t.Run("empty key short-circuits", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Error("server should not be called for empty key")
		}))
		defer srv.Close()
		_, err := New(srv.URL, "acc").WithUserID(7).Redeem(context.Background(), "")
		if err == nil {
			t.Fatal("want error")
		}
	})

	t.Run("posts key + returns quota", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/api/user/topup" {
				t.Errorf("got %s %s", r.Method, r.URL.Path)
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"key":"abc123"`) {
				t.Errorf("body = %s", body)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":true,"data":500000}`))
		}))
		defer srv.Close()
		q, err := New(srv.URL, "acc").WithUserID(7).Redeem(context.Background(), "abc123")
		if err != nil {
			t.Fatalf("Redeem: %v", err)
		}
		if q != 500000 {
			t.Errorf("quota = %d", q)
		}
	})

	t.Run("server error surfaces", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success":false,"message":"redeem failed"}`))
		}))
		defer srv.Close()
		_, err := New(srv.URL, "acc").WithUserID(7).Redeem(context.Background(), "bad")
		if err == nil || !strings.Contains(err.Error(), "redeem failed") {
			t.Errorf("got %v", err)
		}
	})
}

func TestGetCheckinStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/user/checkin" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("month") != "2026-05" {
			t.Errorf("month arg lost: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{
			"enabled":true,"min_quota":100,"max_quota":1000,
			"stats":{
				"total_quota":12345,"total_checkins":42,"checkin_count":3,"checked_in_today":true,
				"records":[
					{"checkin_date":"2026-05-01","quota_awarded":500},
					{"checkin_date":"2026-05-15","quota_awarded":700},
					{"checkin_date":"2026-05-22","quota_awarded":150}
				]
			}
		}}`))
	}))
	defer srv.Close()
	st, err := New(srv.URL, "acc").WithUserID(7).GetCheckinStatus(context.Background(), "2026-05")
	if err != nil {
		t.Fatalf("GetCheckinStatus: %v", err)
	}
	if !st.Enabled || st.MinQuota != 100 || st.MaxQuota != 1000 {
		t.Errorf("scalar fields: %+v", st)
	}
	if st.Stats.TotalQuota != 12345 || st.Stats.TotalCheckins != 42 || st.Stats.CheckinCount != 3 || !st.Stats.CheckedInToday {
		t.Errorf("stats aggregates: %+v", st.Stats)
	}
	if len(st.Stats.Records) != 3 || st.Stats.Records[0].CheckinDate != "2026-05-01" || st.Stats.Records[0].QuotaAwarded != 500 {
		t.Errorf("stats records: %+v", st.Stats.Records)
	}
}

func TestDoCheckin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/user/checkin" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"data":{"quota_awarded":500,"checkin_date":"2026-05-22"}}`))
	}))
	defer srv.Close()
	res, err := New(srv.URL, "acc").WithUserID(7).DoCheckin(context.Background())
	if err != nil {
		t.Fatalf("DoCheckin: %v", err)
	}
	if res.QuotaAwarded != 500 || res.CheckinDate != "2026-05-22" {
		t.Errorf("got %+v", res)
	}
}

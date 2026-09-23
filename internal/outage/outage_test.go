package outage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/none", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"page":{},"status":{"indicator":"none","description":"All Systems Operational"}}`))
	})
	mux.HandleFunc("/minor", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":{"indicator":"minor","description":"Partially Degraded Service"}}`))
	})
	mux.HandleFunc("/major", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":{"indicator":"major","description":"Partial System Outage"}}`))
	})
	mux.HandleFunc("/garbage", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`<html>`)) })
	mux.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tests := []struct {
		path               string
		confirmed, severe  bool
		wantErr            bool
		indicator, descSub string
	}{
		{"/none", false, false, false, "none", "All Systems"},
		{"/minor", true, false, false, "minor", "Degraded"},
		{"/major", true, true, false, "major", "Outage"},
		{"/garbage", false, false, true, "", ""},
		{"/empty", false, false, true, "", ""},
		{"/missing", false, false, true, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r := Check(context.Background(), srv.Client(), srv.URL+tt.path, time.Second)
			if r.Confirmed() != tt.confirmed || r.Severe() != tt.severe || (r.Err != nil) != tt.wantErr || r.Indicator != tt.indicator {
				t.Fatalf("result = %+v", r)
			}
		})
	}
}

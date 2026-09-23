package speed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	fast := Measurement{Status: 200, Bytes: 256 << 10, Duration: 100 * time.Millisecond, Handshake: 20 * time.Millisecond}
	tests := []struct {
		name   string
		target Measurement
		want   bool
		kind   string
	}{
		{"similar", Measurement{Status: 200, Bytes: 256 << 10, Duration: 200 * time.Millisecond, Handshake: 30 * time.Millisecond}, false, ""},
		{"slow throughput", Measurement{Status: 200, Bytes: 128 << 10, Duration: 2 * time.Second, Handshake: 30 * time.Millisecond}, true, "throughput"},
		{"small body ignores rate", Measurement{Status: 200, Bytes: 2 << 10, Duration: 2 * time.Second, Handshake: 30 * time.Millisecond}, false, ""},
		{"slow throughput on an error page is ignored", Measurement{Status: 404, Bytes: 128 << 10, Duration: 2 * time.Second}, false, ""},
		{"slow handshake on 401 still counts", Measurement{Status: 401, Bytes: 1 << 10, Duration: 3 * time.Second, Handshake: 2 * time.Second}, true, "handshake"},
		{"slowish but fast absolute", Measurement{Status: 200, Bytes: 1 << 20, Duration: 2 * time.Second, Handshake: 30 * time.Millisecond}, false, ""},
		{"error", Measurement{Err: errors.New("x")}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Compare(tt.target, fast)
			if r.Throttled != tt.want || r.Kind != tt.kind {
				t.Fatalf("Compare = %+v", r)
			}
		})
	}
	if Compare(fast, Measurement{Err: errors.New("baseline down")}).Throttled {
		t.Fatal("no verdict without a baseline")
	}
	slow := Measurement{Status: 200, Bytes: 128 << 10, Duration: 2 * time.Second}
	if Compare(slow, Measurement{Status: 403, Bytes: 100, Duration: time.Millisecond}).Throttled {
		t.Fatal("a blocked baseline is not a baseline")
	}
}

func TestMeasure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			for i := 0; i < 50; i++ {
				w.Write(make([]byte, 1024))
				w.(http.Flusher).Flush()
				time.Sleep(20 * time.Millisecond)
			}
			return
		}
		w.Write([]byte(strings.Repeat("x", 100<<10)))
	}))
	defer srv.Close()

	m := Measure(context.Background(), srv.Client(), srv.URL+"/", time.Second)
	if m.Err != nil || m.Status != 200 || m.Bytes != 100<<10 || m.Handshake <= 0 {
		t.Fatalf("measurement = %+v", m)
	}
	// A download cut off by the timeout keeps the partial byte count.
	m = Measure(context.Background(), srv.Client(), srv.URL+"/slow", 300*time.Millisecond)
	if m.Err != nil || m.Bytes == 0 || m.Bytes >= 50<<10 {
		t.Fatalf("partial measurement = %+v", m)
	}
}

func TestFormatRate(t *testing.T) {
	for in, want := range map[float64]string{512: "512 B/s", 120 << 10: "120 KB/s", 3 << 20: "3.0 MB/s"} {
		if got := FormatRate(in); got != want {
			t.Errorf("FormatRate(%v) = %q, want %q", in, got, want)
		}
	}
}

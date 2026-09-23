package httpcheck

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/signatures"
	"github.com/assaabriiii/chera/internal/testutil"
)

func TestClassify(t *testing.T) {
	sigs := signatures.Builtin()
	tests := []struct {
		name     string
		host     string
		status   int
		location string
		body     string
		want     Class
	}{
		{"ok", "github.com", 200, "", "User-agent: *", OK},
		{"auth required is fine", "registry-1.docker.io", 401, "", `{"errors":[{"code":"UNAUTHORIZED"}]}`, OK},
		{"redirect to block page", "github.com", 302, "http://10.10.34.34/?type=Invalid Site", "", BlockPage},
		{"block page body", "pypi.org", 200, "", `<iframe src="http://10.10.34.34?type=Invalid Site">`, BlockPage},
		{"openai geo", "api.openai.com", 403, "", `{"error":{"code":"unsupported_country_region_territory"}}`, GeoBlock},
		{"docker geo", "registry-1.docker.io", 403, "", "Since Docker is a US company, we must comply with US export control regulations.", GeoBlock},
		{"plain 403", "api.github.com", 403, "", "rate limited", OK},
		{"451", "example.com", 451, "", "", Legal},
		{"502", "example.com", 502, "", "bad gateway", ServerError},
		{"normal redirect", "github.com", 301, "https://github.com/", "", OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := Classify(sigs, tt.host, tt.status, tt.location, tt.body)
			if got != tt.want {
				t.Fatalf("Classify = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	ca := testutil.NewCA(t, "Test Root")
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "svc.test" || !strings.HasPrefix(r.UserAgent(), "chera") {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte("hello\n world"))
	})
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.10.34.35/", http.StatusFound)
	})
	mux.HandleFunc("/geo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("error code: 1009"))
	})
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) })
	addr := testutil.ServeTLS(t, ca.Leaf(t, "svc.test"), mux, testutil.TLSOptions{})

	o := Options{Dialer: netx.Direct(time.Second), Timeout: 400 * time.Millisecond, RootCAs: ca.Pool, Addr: addr, Signatures: signatures.Builtin()}
	tests := []struct {
		path   string
		class  Class
		status int
	}{
		{"/ok", OK, 200},
		{"/blocked", BlockPage, 302},
		{"/geo", GeoBlock, 403},
		{"/down", ServerError, 503},
		{"/slow", Failed, 0},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r := Fetch(context.Background(), o, "https://svc.test"+tt.path)
			if r.Class != tt.class || r.Status != tt.status {
				t.Fatalf("result = %+v", r)
			}
			if tt.path == "/ok" && r.Snippet != "hello world" {
				t.Fatalf("snippet = %q", r.Snippet)
			}
			if tt.path == "/slow" && r.ErrKind != netx.KindTimeout {
				t.Fatalf("err kind = %s (%v)", r.ErrKind, r.Err)
			}
		})
	}
}

func TestFetchUntrustedNeedsInsecure(t *testing.T) {
	ca := testutil.NewCA(t, "Test Root")
	other := testutil.NewCA(t, "Middlebox")
	addr := testutil.ServeTLS(t, other.Leaf(t, "svc.test"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("see peyvandha.ir"))
	}), testutil.TLSOptions{})
	o := Options{Dialer: netx.Direct(time.Second), Timeout: time.Second, RootCAs: ca.Pool, Addr: addr, Signatures: signatures.Builtin()}
	if r := Fetch(context.Background(), o, "https://svc.test/"); r.Class != Failed {
		t.Fatalf("expected verification failure, got %+v", r)
	}
	o.Insecure = true
	if r := Fetch(context.Background(), o, "https://svc.test/"); r.Class != BlockPage {
		t.Fatalf("expected block page, got %+v", r)
	}
}

func TestSnippet(t *testing.T) {
	long := strings.Repeat("a", 500)
	if got := snippet([]byte(long)); len(got) != 163 {
		t.Fatalf("len = %d", len(got))
	}
	if got := snippet([]byte("a\x00b\tc")); got != "ab c" {
		t.Fatalf("snippet = %q", got)
	}
}

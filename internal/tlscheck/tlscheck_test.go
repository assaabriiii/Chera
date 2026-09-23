package tlscheck

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/testutil"
)

func opts(ca *testutil.CA) Options {
	return Options{Dialer: netx.Direct(time.Second), Timeout: 400 * time.Millisecond, RootCAs: ca.Pool}
}

func TestCheck(t *testing.T) {
	ca := testutil.NewCA(t, "Test Root")
	evil := testutil.NewCA(t, "Fortinet")
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	tests := []struct {
		name        string
		srvOpts     testutil.TLSOptions
		useEvil     bool
		wrongName   bool
		expired     bool
		wantReal    Outcome
		wantProblem string
		wantSNI     bool
		wantExtra   bool
	}{
		{name: "ok", wantReal: OK},
		{name: "sni reset", srvOpts: testutil.TLSOptions{ResetSNI: []string{"blocked.test"}}, wantReal: Reset, wantSNI: true, wantExtra: true},
		{name: "sni stall", srvOpts: testutil.TLSOptions{StallSNI: []string{"blocked.test"}}, wantReal: Timeout, wantSNI: true, wantExtra: true},
		{name: "reset for all", srvOpts: testutil.TLSOptions{ResetAll: true}, wantReal: Reset, wantExtra: true},
		{name: "untrusted issuer", useEvil: true, wantReal: CertInvalid, wantProblem: CertUnknownAuthority},
		{name: "wrong host", wrongName: true, wantReal: CertInvalid, wantProblem: CertHostname},
		{name: "expired", expired: true, wantReal: CertInvalid, wantProblem: CertExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := ca
			if tt.useEvil {
				issuer = evil
			}
			names := []string{"blocked.test", "example.com"}
			if tt.wrongName {
				names = []string{"other.test"}
			}
			cert := issuer.Leaf(t, names...)
			if tt.expired {
				cert = issuer.LeafValidity(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), names...)
			}
			addr := testutil.ServeTLS(t, cert, okHandler, tt.srvOpts)
			res := Check(context.Background(), opts(ca), addr, "blocked.test")
			if res.Real.Outcome != tt.wantReal {
				t.Fatalf("real outcome = %s (%v), want %s", res.Real.Outcome, res.Real.Err, tt.wantReal)
			}
			if res.Real.CertProblem != tt.wantProblem {
				t.Fatalf("cert problem = %q, want %q", res.Real.CertProblem, tt.wantProblem)
			}
			if res.SNIFiltered() != tt.wantSNI {
				t.Fatalf("SNIFiltered = %v, neutral=%+v nosni=%+v", res.SNIFiltered(), res.Neutral, res.NoSNI)
			}
			if (res.Neutral != nil) != tt.wantExtra {
				t.Fatalf("extra handshakes ran = %v, want %v", res.Neutral != nil, tt.wantExtra)
			}
			if tt.useEvil && res.Real.Issuer == "" {
				t.Fatal("issuer not recorded")
			}
		})
	}
}

func TestConnectFailed(t *testing.T) {
	ca := testutil.NewCA(t, "Test Root")
	h := Do(context.Background(), opts(ca), testutil.ClosedAddr(t, "tcp"), "a.test", "a.test")
	if h.Outcome != ConnectFailed || h.Blocked() || h.Reached() {
		t.Fatalf("handshake = %+v", h)
	}
}

func TestResetMidHandshake(t *testing.T) {
	ca := testutil.NewCA(t, "Test Root")
	addr := testutil.ServeReset(t)
	h := Do(context.Background(), opts(ca), addr, "a.test", "a.test")
	if !h.Blocked() {
		t.Fatalf("expected blocked handshake, got %+v", h)
	}
}

func TestAlertCountsAsReached(t *testing.T) {
	h := Handshake{Outcome: Alert}
	if !h.Reached() || h.Blocked() {
		t.Fatal("alert means the server answered")
	}
	r := Result{Real: Handshake{Outcome: Reset}, Neutral: &Handshake{Outcome: Alert}, NoSNI: &Handshake{Outcome: Reset}}
	if !r.SNIFiltered() {
		t.Fatal("alert on neutral SNI should still prove SNI filtering")
	}
}

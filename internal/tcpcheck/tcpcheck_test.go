package tcpcheck

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/testutil"
)

func TestProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	open := netip.MustParseAddrPort(ln.Addr().String())
	closed := netip.MustParseAddrPort(testutil.ClosedAddr(t, "tcp"))
	blackhole := netip.MustParseAddrPort("192.0.2.1:443")

	d := &testutil.FakeDialer{Blackhole: map[string]bool{blackhole.String(): true}}
	tests := []struct {
		name string
		addr netip.AddrPort
		want Outcome
	}{
		{"open", open, OK},
		{"closed port is refused", closed, Refused},
		{"blackhole times out", blackhole, Timeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Probe(context.Background(), d, tt.addr, 300*time.Millisecond)
			if r.Outcome != tt.want {
				t.Fatalf("outcome = %s (%v), want %s", r.Outcome, r.Err, tt.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	a := netip.MustParseAddrPort("1.2.3.4:443")
	tests := []struct {
		name                              string
		in                                []Outcome
		working, timeout, reject, unreach bool
	}{
		{"all ok", []Outcome{OK, OK}, true, false, false, false},
		{"one works", []Outcome{Timeout, OK}, true, false, false, false},
		{"all timeout", []Outcome{Timeout, Timeout}, false, true, false, false},
		{"mixed failures", []Outcome{Timeout, Reset}, false, false, true, false},
		{"refused", []Outcome{Refused}, false, false, true, false},
		{"unreachable", []Outcome{Unreachable}, false, false, false, true},
		{"empty", nil, false, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rs []Result
			for _, o := range tt.in {
				rs = append(rs, Result{Addr: a, Outcome: o})
			}
			s := Summarize(rs)
			if (s.Working != nil) != tt.working || s.AllTimeout != tt.timeout || s.AnyRejected != tt.reject || s.AllUnreachable != tt.unreach {
				t.Fatalf("summary = %+v", s)
			}
		})
	}
}

func TestProbeAllOrder(t *testing.T) {
	closed := netip.MustParseAddrPort(testutil.ClosedAddr(t, "tcp"))
	bh := netip.MustParseAddrPort("192.0.2.9:443")
	d := &testutil.FakeDialer{Blackhole: map[string]bool{bh.String(): true}}
	rs := ProbeAll(context.Background(), d, []netip.AddrPort{bh, closed}, 200*time.Millisecond)
	if rs[0].Outcome != Timeout || rs[1].Outcome != Refused {
		t.Fatalf("results = %+v", rs)
	}
}

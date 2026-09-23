package dnscheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/signatures"
	"github.com/assaabriiii/chera/internal/testutil"
)

type fakeResolver struct {
	name  string
	kind  Kind
	addrs []netip.Addr
	err   error
}

func (f *fakeResolver) Name() string { return f.name }
func (f *fakeResolver) Kind() Kind   { return f.kind }
func (f *fakeResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return f.addrs, f.err
}

func ans(kind Kind, addrs ...string) Answer {
	return Answer{Resolver: string(kind), Kind: kind, Addrs: testutil.Addrs(addrs...)}
}

func failed(kind Kind, err error) Answer {
	return Answer{Resolver: string(kind), Kind: kind, Err: err}
}

func TestAnalyze(t *testing.T) {
	sigs := signatures.Builtin()
	tests := []struct {
		name          string
		res           Result
		poisoned      bool
		blockIPs      int
		bogons        int
		suspects      int
		injected      bool
		systemFailure string
		unresolvable  bool
		refKind       Kind
	}{
		{
			name:    "clean",
			res:     Result{System: ans(KindSystem, "140.82.121.4"), DoH: []Answer{ans(KindDoH, "140.82.121.4", "140.82.121.3")}},
			refKind: KindDoH,
		},
		{
			name:     "block page ip",
			res:      Result{System: ans(KindSystem, "10.10.34.35"), DoH: []Answer{ans(KindDoH, "140.82.121.4")}},
			poisoned: true, blockIPs: 1, refKind: KindDoH,
		},
		{
			name:     "private ip",
			res:      Result{System: ans(KindSystem, "192.168.1.10"), DoH: []Answer{ans(KindDoH, "151.101.0.223")}},
			poisoned: true, bogons: 1, refKind: KindDoH,
		},
		{
			name:     "cdn mismatch is only suspect",
			res:      Result{System: ans(KindSystem, "151.101.128.223"), DoH: []Answer{ans(KindDoH, "151.101.0.223")}},
			suspects: 1, refKind: KindDoH,
		},
		{
			name: "injected on public udp",
			res: Result{
				System: ans(KindSystem, "10.10.34.36"),
				Public: []Answer{ans(KindUDP, "10.10.34.36")},
				DoH:    []Answer{ans(KindDoH, "104.16.0.35")},
			},
			poisoned: true, blockIPs: 1, injected: true, refKind: KindDoH,
		},
		{
			name: "custom udp resolver under test is not injection",
			res: Result{
				System: Answer{Resolver: "resolver:10.0.0.1:53", Kind: KindUDP, Addrs: testutil.Addrs("10.10.34.36")},
				DoH:    []Answer{ans(KindDoH, "104.16.0.35")},
			},
			poisoned: true, blockIPs: 1, refKind: KindDoH,
		},
		{
			name:          "system nxdomain",
			res:           Result{System: failed(KindSystem, ErrNXDomain), DoH: []Answer{ans(KindDoH, "1.2.3.4")}},
			systemFailure: "nxdomain", refKind: KindDoH,
		},
		{
			name:         "nothing resolves",
			res:          Result{System: failed(KindSystem, ErrNXDomain), DoH: []Answer{failed(KindDoH, errors.New("x"))}},
			unresolvable: true,
		},
		{
			name: "doh blocked, fall back to public udp",
			res: Result{
				System: ans(KindSystem, "10.10.34.34"),
				Public: []Answer{ans(KindUDP, "140.82.121.4")},
				DoH:    []Answer{failed(KindDoH, context.DeadlineExceeded)},
			},
			poisoned: true, blockIPs: 1, refKind: KindUDP,
		},
		{
			name:    "loopback everywhere is not poisoning",
			res:     Result{System: ans(KindSystem, "127.0.0.1"), DoH: []Answer{ans(KindDoH, "127.0.0.1")}},
			refKind: KindDoH,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Analyze(tt.res, sigs)
			if a.Poisoned() != tt.poisoned || len(a.BlockIPs) != tt.blockIPs || len(a.Bogons) != tt.bogons ||
				len(a.Suspects) != tt.suspects || a.InjectedPublic != tt.injected ||
				a.SystemFailure != tt.systemFailure || a.Unresolvable != tt.unresolvable || a.ReferenceKind != tt.refKind {
				t.Fatalf("analysis = %+v", a)
			}
		})
	}
}

func TestIsBogon(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.10.34.35": true, "127.0.0.1": true, "0.0.0.0": true, "100.64.1.1": true,
		"169.254.1.1": true, "198.18.0.1": true, "224.0.0.1": true,
		"140.82.121.4": false, "8.8.8.8": false,
	} {
		if got := IsBogon(netip.MustParseAddr(ip)); got != want {
			t.Errorf("IsBogon(%s) = %v", ip, got)
		}
	}
}

func TestResolveConcurrent(t *testing.T) {
	rs := Resolvers{
		System: &fakeResolver{name: "system", kind: KindSystem, addrs: testutil.Addrs("1.1.1.1")},
		Public: []Resolver{&fakeResolver{name: "p", kind: KindUDP, err: ErrNXDomain}},
		DoH:    []Resolver{&fakeResolver{name: "d", kind: KindDoH, addrs: testutil.Addrs("2.2.2.2")}},
	}
	r := Resolve(context.Background(), "a.com", rs, time.Second)
	if !r.System.OK() || r.Public[0].FailureKind() != "nxdomain" || !r.DoH[0].OK() || r.DoH[0].Resolver != "d" {
		t.Fatalf("result = %+v", r)
	}
}

func TestUDPResolver(t *testing.T) {
	srv := testutil.NewDNSServer(t, testutil.Answers{"github.com": testutil.Addrs("140.82.121.4")})
	u := &UDP{Addr: srv.Addr}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addrs, err := u.Lookup(ctx, "GitHub.com")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "140.82.121.4" {
		t.Fatalf("lookup = %v, %v", addrs, err)
	}
	if _, err := u.Lookup(ctx, "missing.example"); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("missing: %v", err)
	}
}

func TestUDPResolverTimeout(t *testing.T) {
	// A bound socket that never answers.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	a := Answer{}
	_, a.Err = (&UDP{Addr: pc.LocalAddr().String()}).Lookup(ctx, "a.com")
	if a.FailureKind() != "timeout" {
		t.Fatalf("failure = %q (%v)", a.FailureKind(), a.Err)
	}
}

func TestDoHResolver(t *testing.T) {
	ca := testutil.NewCA(t, "Test DoH CA")
	addr := testutil.ServeTLS(t, ca.Leaf(t, "dns.test"), testutil.DoHHandler(testutil.Answers{
		"pypi.org": testutil.Addrs("151.101.0.223", "151.101.64.223"),
	}), testutil.TLSOptions{})
	d := NewDoH("test", "https://dns.test/dns-query", addr, netx.Direct(time.Second), ca.Pool, time.Second)
	defer d.CloseIdle()
	addrs, err := d.Lookup(context.Background(), "pypi.org")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("lookup = %v, %v", addrs, err)
	}
	if _, err := d.Lookup(context.Background(), "nope.example"); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("nxdomain: %v", err)
	}

	// Wrong trust roots must fail: DoH is only useful if it is authenticated.
	bad := NewDoH("test", "https://dns.test/dns-query", addr, netx.Direct(time.Second), testutil.NewCA(t, "Other").Pool, time.Second)
	if _, err := bad.Lookup(context.Background(), "pypi.org"); err == nil {
		t.Fatal("expected certificate error")
	}
}

func TestDoHHTTPError(t *testing.T) {
	ca := testutil.NewCA(t, "Test DoH CA")
	addr := testutil.ServeTLS(t, ca.Leaf(t, "dns.test"), http.NotFoundHandler(), testutil.TLSOptions{})
	d := NewDoH("", "https://dns.test/dns-query", addr, netx.Direct(time.Second), ca.Pool, time.Second)
	if _, err := d.Lookup(context.Background(), "a.com"); err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

func TestSystemResolver(t *testing.T) {
	srv := testutil.NewDNSServer(t, testutil.Answers{"example.test": testutil.Addrs("192.0.2.1")})
	s := &System{R: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", srv.Addr)
		},
	}}
	addrs, err := s.Lookup(context.Background(), "example.test")
	if err != nil || addrs[0].String() != "192.0.2.1" {
		t.Fatalf("lookup = %v, %v", addrs, err)
	}
	if _, err := s.Lookup(context.Background(), "missing.test"); !errors.Is(err, ErrNXDomain) {
		t.Fatalf("missing: %v", err)
	}
}

func TestInterception(t *testing.T) {
	hijacker := testutil.NewDNSServer(t, testutil.Answers{"example.com": testutil.Addrs("10.10.34.34")})
	got := CheckInterception(context.Background(), hijacker.Addr, time.Second)
	if !got.Detected || len(got.Addrs) != 1 {
		t.Fatalf("expected detection: %+v", got)
	}
	clean := CheckInterception(context.Background(), testutil.ClosedAddr(t, "udp"), 300*time.Millisecond)
	if clean.Detected {
		t.Fatalf("false positive: %+v", clean)
	}
}

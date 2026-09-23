package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/localnet"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/testutil"
)

// scenario describes a simulated network. Each integration test builds
// one, runs the full pipeline against it and checks the verdict.
type scenario struct {
	host string
	// systemDNS and dohDNS are what the resolver under test and the DoH
	// reference return for host. nil means NXDOMAIN.
	systemDNS []netip.Addr
	dohDNS    []netip.Addr
	// handler serves HTTPS on the target address.
	handler http.Handler
	tlsOpts testutil.TLSOptions
	// untrusted serves a certificate from a CA the client does not trust.
	untrusted bool
	// closedPort makes the verified address refuse connections.
	closedPort bool
	// blackhole makes connections to these addresses hang.
	blackhole []string
	// hijackDNS makes the interception probe answer.
	hijackDNS bool
	// noRoute simulates a machine without a default route.
	noRoute bool
	// statusIndicator, when set, is served by a fake status page.
	statusIndicator string
	// speed enables the throttling layer with a fast local baseline.
	speed bool
}

type harness struct {
	cfg       Config
	dialer    *testutil.FakeDialer
	statusURL string
}

func okHandler(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
}

// slowHandler answers the HTTP check quickly but trickles a larger body,
// like a throttled link: about 100 KB/s.
func slowHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 24; i++ {
			w.Write(make([]byte, 4<<10))
			w.(http.Flusher).Flush()
			time.Sleep(40 * time.Millisecond)
		}
	})
}

func setup(t *testing.T, sc scenario) *harness {
	t.Helper()
	ca := testutil.NewCA(t, "Test Root")

	handler := sc.handler
	if handler == nil {
		handler = okHandler(200, "ok")
	}
	certCA := ca
	if sc.untrusted {
		certCA = testutil.NewCA(t, "Unknown Middlebox")
	}
	targetAddr := testutil.ServeTLS(t, certCA.Leaf(t, sc.host, "example.com"), handler, sc.tlsOpts)
	_, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)
	if sc.closedPort {
		_, p, _ := net.SplitHostPort(testutil.ClosedAddr(t, "tcp"))
		port, _ = strconv.Atoi(p)
	}

	dohAnswers := testutil.Answers{}
	if sc.dohDNS != nil {
		dohAnswers[sc.host] = sc.dohDNS
	}
	dohAddr := testutil.ServeTLS(t, ca.Leaf(t, "doh.test"), testutil.DoHHandler(dohAnswers), testutil.TLSOptions{})
	sysAnswers := testutil.Answers{}
	if sc.systemDNS != nil {
		sysAnswers[sc.host] = sc.systemDNS
	}
	sysDNS := testutil.NewDNSServer(t, sysAnswers)

	intercept := testutil.ClosedAddr(t, "udp")
	if sc.hijackDNS {
		intercept = testutil.NewDNSServer(t, testutil.Answers{"example.com": testutil.Addrs("10.10.34.34")}).Addr
	}

	baseline, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { baseline.Close() })

	d := &testutil.FakeDialer{Blackhole: map[string]bool{}}
	for _, a := range sc.blackhole {
		d.Blackhole[net.JoinHostPort(a, strconv.Itoa(port))] = true
	}

	var statusURL string
	if sc.statusIndicator != "" {
		st := httptest.NewServer(okHandler(200, `{"status":{"indicator":"`+sc.statusIndicator+`","description":"Major Service Outage"}}`))
		t.Cleanup(st.Close)
		statusURL = st.URL
	}
	baselineSpeed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 256<<10))
	}))
	t.Cleanup(baselineSpeed.Close)

	timeout := time.Second
	cfg := Config{
		Speed:            sc.speed,
		SpeedBaselineURL: baselineSpeed.URL,
		Timeout:          timeout,
		Concurrency:      4,
		Dialer:           d,
		RootCAs:          ca.Pool,
		Port:             port,
		Resolvers: dnscheck.Resolvers{
			System: &dnscheck.System{R: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					var nd net.Dialer
					return nd.DialContext(ctx, "udp", sysDNS.Addr)
				},
			}},
			DoH: []dnscheck.Resolver{dnscheck.NewDoH("doh:test", "https://doh.test/dns-query", dohAddr, netx.Direct(timeout), ca.Pool, timeout)},
		},
		InterceptionProbe: intercept,
		Local: &localnet.Config{
			Dialer:   d,
			Timeout:  timeout,
			Baseline: []string{baseline.Addr().String()},
			Interfaces: func() ([]localnet.Iface, error) {
				return []localnet.Iface{{Name: "eth0", Up: true, HasAddr: true}}, nil
			},
			Route:       func() bool { return !sc.noRoute },
			Getenv:      func(string) string { return "" },
			SystemProxy: func(context.Context) string { return "" },
		},
	}
	return &harness{cfg: cfg, dialer: d, statusURL: statusURL}
}

func (h *harness) run(t *testing.T, host string) model.TargetReport {
	t.Helper()
	rep := New(h.cfg).Run(context.Background(), []model.Target{{Host: host, StatusPage: h.statusURL}})
	if len(rep.Targets) != 1 {
		t.Fatalf("got %d targets", len(rep.Targets))
	}
	return rep.Targets[0]
}

func TestIntegrationVerdicts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration tests use local servers and timeouts")
	}
	lo := testutil.Addrs("127.0.0.1")
	tests := []struct {
		name string
		sc   scenario
		want model.Verdict
		conf model.Confidence
		also []model.Verdict
	}{
		{"ok", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo}, model.OK, model.High, nil},
		{"local network down", scenario{host: "svc.test", systemDNS: lo, dohDNS: testutil.Addrs("127.0.0.2"), blackhole: []string{"127.0.0.2"}, noRoute: true},
			model.LocalNetworkDown, model.High, nil},
		{"dns poisoned", scenario{host: "svc.test", systemDNS: testutil.Addrs("10.10.34.35"), dohDNS: lo}, model.DNSPoisoned, model.High, nil},
		{"dns nxdomain", scenario{host: "svc.test", systemDNS: nil, dohDNS: lo}, model.DNSPoisoned, model.Medium, nil},
		{"dns intercepted", scenario{host: "svc.test", systemDNS: testutil.Addrs("10.10.34.36"), dohDNS: lo, hijackDNS: true}, model.DNSIntercepted, model.High, nil},
		{"ip blocked", scenario{host: "svc.test", systemDNS: testutil.Addrs("127.0.0.2"), dohDNS: testutil.Addrs("127.0.0.2"), blackhole: []string{"127.0.0.2"}},
			model.IPBlocked, model.High, nil},
		{"connection reset", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, closedPort: true}, model.ConnectionReset, model.Medium, nil},
		{"sni filtered", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, tlsOpts: testutil.TLSOptions{ResetSNI: []string{"svc.test"}}},
			model.SNIFiltered, model.High, nil},
		{"sni filtered by drop plus poisoned dns", scenario{host: "svc.test", systemDNS: testutil.Addrs("10.10.34.35"), dohDNS: lo, tlsOpts: testutil.TLSOptions{StallSNI: []string{"svc.test"}}},
			model.SNIFiltered, model.High, []model.Verdict{model.DNSPoisoned}},
		{"tls intercepted", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, untrusted: true}, model.TLSIntercepted, model.High, nil},
		{"block page", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, handler: okHandler(200, `<iframe src="http://10.10.34.34?type=Invalid Site&policy=MainPolicy"></iframe>`)},
			model.BlockPage, model.High, nil},
		{"provider geo block", scenario{host: "api.openai.com", systemDNS: lo, dohDNS: lo,
			handler: okHandler(403, `{"error":{"code":"unsupported_country_region_territory","message":"Country, region, or territory not supported"}}`)},
			model.ProviderGeoBlock, model.High, nil},
		{"upstream outage", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, handler: okHandler(503, "unavailable")}, model.UpstreamOutage, model.Medium, nil},
		{"upstream outage confirmed", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, handler: okHandler(502, "bad gateway"), statusIndicator: "major"},
			model.UpstreamOutage, model.High, nil},
		{"throttled", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, speed: true, handler: slowHandler()}, model.Throttled, model.Medium, nil},
		{"speed check on a fast service", scenario{host: "svc.test", systemDNS: lo, dohDNS: lo, speed: true, handler: okHandler(200, string(make([]byte, 128<<10)))},
			model.OK, model.High, nil},
		{"inconclusive", scenario{host: "svc.test"}, model.Inconclusive, model.Low, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := setup(t, tt.sc)
			got := h.run(t, tt.sc.host)
			if got.Verdict != tt.want || got.Confidence != tt.conf {
				t.Errorf("verdict = %s (%s), want %s (%s), reason %+v", got.Verdict, got.Confidence, tt.want, tt.conf, got.Reason)
				for _, e := range got.Evidence {
					t.Logf("  [%s] %s %s: %s", e.Layer, e.Status, e.Check, e.Detail)
				}
			}
			if len(got.Also) != len(tt.also) || (len(tt.also) > 0 && got.Also[0] != tt.also[0]) {
				t.Errorf("also = %v, want %v", got.Also, tt.also)
			}
			if len(got.Evidence) == 0 {
				t.Error("no evidence recorded")
			}
		})
	}
}

// TestGentle checks that a healthy target costs only a handful of
// connections: no retries, no extra SNI handshakes.
func TestGentle(t *testing.T) {
	lo := testutil.Addrs("127.0.0.1")
	h := setup(t, scenario{host: "svc.test", systemDNS: lo, dohDNS: lo})
	if got := h.run(t, "svc.test"); got.Verdict != model.OK {
		t.Fatalf("verdict = %s", got.Verdict)
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(h.cfg.Port))
	// One TCP probe, one TLS handshake, one HTTP request.
	if n := h.dialer.Count(target); n != 3 {
		t.Fatalf("dialed target %d times, want 3", n)
	}
}

func TestReportOrderAndLocalSummary(t *testing.T) {
	lo := testutil.Addrs("127.0.0.1")
	h := setup(t, scenario{host: "svc.test", systemDNS: lo, dohDNS: lo})
	rep := New(h.cfg).Run(context.Background(), []model.Target{{Host: "svc.test"}, {Host: "missing.test"}, {Host: "svc.test", URL: "https://svc.test/x"}})
	if rep.Targets[0].Target.Host != "svc.test" || rep.Targets[1].Target.Host != "missing.test" || rep.Targets[2].Target.URL == "" {
		t.Fatal("order not preserved")
	}
	if !rep.Local.Up || len(rep.Local.Reachable) != 1 || rep.Local.DNSIntercept {
		t.Fatalf("local summary = %+v", rep.Local)
	}
	if rep.Targets[1].Verdict != model.Inconclusive {
		t.Fatalf("missing host verdict = %s", rep.Targets[1].Verdict)
	}
}

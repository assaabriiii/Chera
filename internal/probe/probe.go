// Package probe runs the diagnosis layers for each target and hands the
// collected evidence to the verdict engine.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/httpcheck"
	"github.com/assaabriiii/chera/internal/localnet"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/outage"
	"github.com/assaabriiii/chera/internal/signatures"
	"github.com/assaabriiii/chera/internal/speed"
	"github.com/assaabriiii/chera/internal/tcpcheck"
	"github.com/assaabriiii/chera/internal/tlscheck"
	"github.com/assaabriiii/chera/internal/verdict"
)

// Config holds everything the layers need. Tests fill it with fakes; the
// CLI fills it with real resolvers and dialers via ApplyDefaults.
type Config struct {
	// Timeout bounds each individual network operation.
	Timeout time.Duration
	// Concurrency is the number of targets checked in parallel.
	Concurrency int
	// Dialer is used for every TCP connection (direct or through --proxy).
	Dialer netx.Dialer
	// ProxyInUse is true when Dialer tunnels through a user proxy.
	ProxyInUse bool
	// Signatures recognise block pages, injected IPs and geo-blocks.
	Signatures *signatures.Set
	// Version is recorded in the report.
	Version string
	// Speed enables the throttling layer.
	Speed bool

	// Resolvers are consulted by the DNS layer.
	Resolvers dnscheck.Resolvers
	// InterceptionProbe is a UDP address with no DNS server behind it; an
	// answer from it means DNS is hijacked. Empty disables the check.
	InterceptionProbe string
	// RootCAs verifies certificates; nil means the system pool.
	RootCAs *x509.CertPool
	// Port is the TCP port for TCP, TLS and HTTPS checks (443 in real use).
	Port int
	// NeutralSNI is the server name used to test SNI filtering.
	NeutralSNI string
	// MaxAddrs limits how many of a target's addresses are probed.
	MaxAddrs int
	// Local configures the local network layer; nil skips it.
	Local *localnet.Config
	// HTTPClient fetches status pages and the speed baseline.
	HTTPClient *http.Client
	// SpeedBaselineURL is downloaded to compare throughput against.
	SpeedBaselineURL string
}

// Runner executes the pipeline.
type Runner struct {
	cfg Config
}

func fillDefaults(cfg *Config) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Dialer == nil {
		cfg.Dialer = netx.Direct(cfg.Timeout)
	}
	if cfg.Signatures == nil {
		cfg.Signatures = signatures.Builtin()
	}
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	if cfg.NeutralSNI == "" {
		cfg.NeutralSNI = tlscheck.DefaultNeutralSNI
	}
	if cfg.MaxAddrs <= 0 {
		cfg.MaxAddrs = 2
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Transport: pinnedTransport(cfg, "")}
	}
	if cfg.SpeedBaselineURL == "" {
		cfg.SpeedBaselineURL = speed.DefaultBaselineURL
	}
}

// pinnedTransport returns an HTTP transport that uses cfg.Dialer and,
// when addr is set, sends every connection to that verified address.
func pinnedTransport(cfg *Config, addr string) *http.Transport {
	d := cfg.Dialer
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			if addr != "" {
				a = addr
			}
			return d.DialContext(ctx, network, a)
		},
		TLSClientConfig:     &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: cfg.Timeout,
		DisableKeepAlives:   addr != "",
	}
}

// New returns a Runner, filling unset fields with safe defaults.
func New(cfg Config) *Runner {
	fillDefaults(&cfg)
	return &Runner{cfg: cfg}
}

// shared holds results that are measured once per run, not per target.
type shared struct {
	intercept *dnscheck.Interception
	local     *localnet.Result

	baselineOnce sync.Once
	baseline     speed.Measurement
}

// Run diagnoses all targets and returns the report. Targets keep their
// input order in the report.
func (r *Runner) Run(ctx context.Context, targets []model.Target) *model.Report {
	start := time.Now()
	rep := &model.Report{
		Version: r.cfg.Version,
		Started: start.UTC(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		Targets: make([]model.TargetReport, len(targets)),
	}

	var sh shared
	var wg sync.WaitGroup
	if r.cfg.InterceptionProbe != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ic := dnscheck.CheckInterception(ctx, r.cfg.InterceptionProbe, r.cfg.Timeout)
			sh.intercept = &ic
		}()
	}
	if r.cfg.Local != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lr := localnet.Check(ctx, *r.cfg.Local)
			sh.local = &lr
		}()
	}
	wg.Wait()
	rep.Local = localSummary(&sh, r.cfg.ProxyInUse)

	sem := make(chan struct{}, r.cfg.Concurrency)
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t model.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ts := time.Now()
			tr := r.checkTarget(ctx, t, &sh)
			tr.Duration = time.Since(ts)
			rep.Targets[i] = tr
		}(i, t)
	}
	wg.Wait()
	rep.Duration = time.Since(start)
	return rep
}

func localSummary(sh *shared, proxy bool) model.LocalSummary {
	ls := model.LocalSummary{Up: true, DefaultRoute: true, ProxyFlag: proxy}
	if sh.intercept != nil {
		ls.DNSIntercept = sh.intercept.Detected
	}
	if l := sh.local; l != nil {
		down, _ := l.Down()
		ls.Up = !down
		ls.DefaultRoute = l.DefaultRoute
		for _, i := range l.Interfaces {
			if i.Up && !i.Loop && i.HasAddr {
				ls.Interfaces = append(ls.Interfaces, i.Name)
			}
		}
		ls.VPNInterfaces = l.VPNNames()
		ls.ProxyEnv = l.ProxyEnv
		ls.SystemProxy = l.SystemProxy
		for _, p := range l.Baseline {
			if p.OK {
				ls.Reachable = append(ls.Reachable, p.Addr)
			} else {
				ls.Unreachable = append(ls.Unreachable, p.Addr)
			}
		}
	}
	return ls
}

// run collects every layer's result for one target.
type run struct {
	target   model.Target
	shared   *shared
	dns      dnscheck.Result
	analysis dnscheck.Analysis
	resolved bool
	tcp      []tcpcheck.Result
	tls      *tlscheck.Result
	// verify is a handshake to a suspect system-DNS address, checking
	// whether it really serves this host.
	verify *tlscheck.Handshake
	http   *httpcheck.Result
	outage *outage.Result
	speed  *speed.Result
}

func (r *Runner) tlsOptions() tlscheck.Options {
	return tlscheck.Options{Dialer: r.cfg.Dialer, Timeout: r.cfg.Timeout, RootCAs: r.cfg.RootCAs, NeutralSNI: r.cfg.NeutralSNI}
}

func (r *Runner) addrPort(a netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(a, uint16(r.cfg.Port))
}

func (r *Runner) checkTarget(ctx context.Context, t model.Target, sh *shared) model.TargetReport {
	st := &run{target: t, shared: sh}

	// Layer 2: DNS.
	st.dns = dnscheck.Resolve(ctx, t.Host, r.cfg.Resolvers, r.cfg.Timeout)
	st.analysis = dnscheck.Analyze(st.dns, r.cfg.Signatures)
	st.resolved = true

	var wg sync.WaitGroup
	if len(st.analysis.Suspects) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := tlscheck.Do(ctx, r.tlsOptions(), r.addrPort(st.analysis.Suspects[0]).String(), t.Host, t.Host)
			st.verify = &h
		}()
	}

	// Layer 3: TCP to the reference (correct) addresses.
	var addrs []netip.AddrPort
	for _, a := range st.analysis.Reference {
		if len(addrs) == r.cfg.MaxAddrs {
			break
		}
		addrs = append(addrs, r.addrPort(a))
	}
	if len(addrs) > 0 {
		st.tcp = tcpcheck.ProbeAll(ctx, r.cfg.Dialer, addrs, r.cfg.Timeout)
	}

	// Layer 4: TLS/SNI on the first address that accepted a connection.
	if w := tcpcheck.Summarize(st.tcp).Working; w != nil {
		res := tlscheck.Check(ctx, r.tlsOptions(), w.Addr.String(), t.Host)
		st.tls = &res

		// Layer 5: HTTP, when the handshake completed. An untrusted
		// certificate is followed insecurely only to see what the
		// intercepting middlebox serves.
		if o := res.Real.Outcome; o == tlscheck.OK || o == tlscheck.CertInvalid {
			hr := httpcheck.Fetch(ctx, httpcheck.Options{
				Dialer:     r.cfg.Dialer,
				Timeout:    r.cfg.Timeout,
				RootCAs:    r.cfg.RootCAs,
				Addr:       w.Addr.String(),
				Insecure:   o == tlscheck.CertInvalid,
				Signatures: r.cfg.Signatures,
			}, t.CheckURL())
			st.http = &hr
		}

		// Layer 6: throttling, only on request and only when the service
		// answers normally.
		if r.cfg.Speed && st.http != nil && st.http.Class == httpcheck.OK {
			st.speed = r.measureSpeed(ctx, t, w.Addr.String(), sh)
		}
	}
	wg.Wait()

	// Layer 7: when the path looks clean but the service fails, ask its
	// status page.
	if t.StatusPage != "" && r.pathCleanButFailing(st) {
		o := outage.Check(ctx, r.cfg.HTTPClient, t.StatusPage, r.cfg.Timeout)
		st.outage = &o
	}

	d := verdict.Decide(verdict.Input{
		Local:      sh.local,
		Intercept:  sh.intercept,
		DNS:        st.analysis,
		TCP:        st.tcp,
		TLS:        st.tls,
		Verify:     st.verify,
		HTTP:       st.http,
		Outage:     st.outage,
		Speed:      st.speed,
		Signatures: r.cfg.Signatures,
	})
	return model.TargetReport{
		Target:     t,
		Verdict:    d.Verdict,
		Confidence: d.Confidence,
		Reason:     d.Reason,
		Also:       d.Also,
		Evidence:   evidence(st),
	}
}

func (r *Runner) pathCleanButFailing(st *run) bool {
	if st.analysis.Unresolvable {
		return true
	}
	if st.tls == nil || st.tls.Real.Outcome != tlscheck.OK || st.http == nil {
		return false
	}
	return st.http.Class == httpcheck.ServerError || st.http.Class == httpcheck.Failed
}

func (r *Runner) measureSpeed(ctx context.Context, t model.Target, addr string, sh *shared) *speed.Result {
	timeout := 2 * r.cfg.Timeout
	sh.baselineOnce.Do(func() {
		sh.baseline = speed.Measure(ctx, r.cfg.HTTPClient, r.cfg.SpeedBaselineURL, timeout)
	})
	u := t.SpeedURL
	if u == "" {
		u = t.CheckURL()
	}
	client := &http.Client{
		Transport:     pinnedTransport(&r.cfg, addr),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	m := speed.Measure(ctx, client, u, timeout)
	res := speed.Compare(m, sh.baseline)
	return &res
}

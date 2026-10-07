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
	// ControlName is resolved when every plain resolver times out for a
	// target, to tell dropped queries apart from dead resolvers.
	ControlName string
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
	if cfg.ControlName == "" {
		cfg.ControlName = DefaultControlName
	}
}

// DefaultControlName is a stable name that filters have no reason to block.
const DefaultControlName = "example.com"

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

// interceptionTimeout caps the DNS interception probe. A hijacked query is
// answered as fast as any other, so waiting the full per-operation timeout
// for a reply that normally never comes only slows the run down.
const interceptionTimeout = 2 * time.Second

// shared holds results that are measured once per run, not per target.
// intercept and local may only be read after done is closed.
type shared struct {
	done      chan struct{}
	intercept *dnscheck.Interception
	local     *localnet.Result

	baselineOnce sync.Once
	baseline     speed.Measurement

	controlOnce sync.Once
	control     dnscheck.Result
}

// controlResolves reports whether any plain resolver answers the control
// name. It is looked up at most once per run.
func (r *Runner) controlResolves(ctx context.Context, sh *shared) (dnscheck.Result, bool) {
	sh.controlOnce.Do(func() {
		rs := dnscheck.Resolvers{System: r.cfg.Resolvers.System, Public: r.cfg.Resolvers.Public}
		sh.control = dnscheck.Resolve(ctx, r.cfg.ControlName, rs, r.cfg.Timeout)
	})
	for _, a := range append([]dnscheck.Answer{sh.control.System}, sh.control.Public...) {
		if a.OK() {
			return sh.control, true
		}
	}
	return sh.control, false
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

	// The run-wide checks overlap with the per-target layers: the
	// interception probe normally waits out its whole timeout, and nothing
	// but the final verdict needs its result.
	sh := &shared{done: make(chan struct{})}
	var swg sync.WaitGroup
	if r.cfg.InterceptionProbe != "" {
		swg.Add(1)
		go func() {
			defer swg.Done()
			ic := dnscheck.CheckInterception(ctx, r.cfg.InterceptionProbe, min(r.cfg.Timeout, interceptionTimeout))
			sh.intercept = &ic
		}()
	}
	if r.cfg.Local != nil {
		swg.Add(1)
		go func() {
			defer swg.Done()
			lr := localnet.Check(ctx, *r.cfg.Local)
			sh.local = &lr
		}()
	}
	go func() {
		swg.Wait()
		close(sh.done)
	}()

	var wg sync.WaitGroup
	dohDown := make([]bool, len(targets))
	sem := make(chan struct{}, r.cfg.Concurrency)
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t model.Target) {
			defer wg.Done()
			sem <- struct{}{}
			ts := time.Now()
			st := r.checkTarget(ctx, t, sh)
			d := time.Since(ts)
			dohDown[i] = st.analysis.DoHUnavailable
			<-sem
			<-sh.done
			tr := r.decide(st)
			tr.Duration = d
			rep.Targets[i] = tr
		}(i, t)
	}
	wg.Wait()
	<-sh.done
	rep.Local = localSummary(sh, r.cfg.ProxyInUse)
	rep.Local.DoHUnreachable = len(targets) > 0
	for _, down := range dohDown {
		rep.Local.DoHUnreachable = rep.Local.DoHUnreachable && down
	}
	rep.Duration = time.Since(start)
	return rep
}

func localSummary(sh *shared, proxy bool) model.LocalSummary {
	ls := model.LocalSummary{Up: true, DefaultRoute: true, ProxyFlag: proxy}
	if sh.intercept != nil {
		ls.DNSIntercept = sh.intercept.Detected
	}
	if l := sh.local; l != nil {
		down, why := l.Down()
		ls.Up = !down
		ls.DownReason = why
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
	// control is the lookup of a control name, done only when every plain
	// resolver timed out for this target.
	control *dnscheck.Result
	tcp     []tcpcheck.Result
	tls     *tlscheck.Result
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

// checkTarget runs every layer for one target. It does not read the
// run-wide results, which may still be in progress.
func (r *Runner) checkTarget(ctx context.Context, t model.Target, sh *shared) *run {
	st := &run{target: t, shared: sh}

	// Layer 2: DNS.
	st.dns = dnscheck.Resolve(ctx, t.Host, r.cfg.Resolvers, r.cfg.Timeout)
	st.analysis = dnscheck.Analyze(st.dns, r.cfg.Signatures)
	st.resolved = true
	if st.analysis.Unresolvable && st.analysis.AllPlainTimeout {
		ctl, ok := r.controlResolves(ctx, sh)
		st.control = &ctl
		st.analysis.Dropped = ok
	}

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

	return st
}

// decide combines a target's layer results with the run-wide ones. It must
// only be called after the shared checks are done.
func (r *Runner) decide(st *run) model.TargetReport {
	sh := st.shared
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
		Target:     st.target,
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

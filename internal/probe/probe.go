// Package probe runs the diagnosis layers for each target and hands the
// collected evidence to the verdict engine.
package probe

import (
	"context"
	"crypto/x509"
	"runtime"
	"sync"
	"time"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/signatures"
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
}

// New returns a Runner, filling unset fields with safe defaults.
func New(cfg Config) *Runner {
	fillDefaults(&cfg)
	return &Runner{cfg: cfg}
}

// shared holds results that are measured once per run, not per target.
type shared struct {
	intercept *dnscheck.Interception
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
	rep.Local.ProxyFlag = r.cfg.ProxyInUse

	var sh shared
	if r.cfg.InterceptionProbe != "" {
		ic := dnscheck.CheckInterception(ctx, r.cfg.InterceptionProbe, r.cfg.Timeout)
		sh.intercept = &ic
		rep.Local.DNSIntercept = ic.Detected
	}

	sem := make(chan struct{}, r.cfg.Concurrency)
	var wg sync.WaitGroup
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

// run collects every layer's result for one target.
type run struct {
	target   model.Target
	shared   *shared
	dns      dnscheck.Result
	analysis dnscheck.Analysis
	resolved bool
}

func (r *Runner) checkTarget(ctx context.Context, t model.Target, sh *shared) model.TargetReport {
	st := &run{target: t, shared: sh}

	st.dns = dnscheck.Resolve(ctx, t.Host, r.cfg.Resolvers, r.cfg.Timeout)
	st.analysis = dnscheck.Analyze(st.dns, r.cfg.Signatures)
	st.resolved = true

	return model.TargetReport{
		Target:     t,
		Verdict:    model.Inconclusive,
		Confidence: model.Low,
		Reason:     model.Reason{Key: "inconclusive"},
		Evidence:   evidence(st),
	}
}

// Package cli implements the chera command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/assaabriiii/chera/internal/i18n"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/presets"
	"github.com/assaabriiii/chera/internal/probe"
	"github.com/assaabriiii/chera/internal/report"
	"github.com/assaabriiii/chera/internal/signatures"
)

// Exit codes.
const (
	ExitOK       = 0 // every target is OK
	ExitProblems = 1 // at least one target is not OK
	ExitUsage    = 2 // bad flags or configuration
)

// Options are the parsed command-line flags.
type Options struct {
	Preset         string
	JSON           bool
	Markdown       bool
	Verbose        bool
	Timeout        time.Duration
	Proxy          string
	Resolver       string
	Speed          bool
	Lang           string
	Concurrency    int
	NoColor        bool
	ListPresets    bool
	PresetsFile    string
	SignaturesFile string
	Version        bool
	Targets        []string
}

// Env abstracts the process environment for testing.
type Env struct {
	Stdout *os.File
	Out    io.Writer
	Err    io.Writer
	Getenv func(string) string
	// Run executes the diagnosis; replaced in tests.
	Run func(ctx context.Context, cfg probe.Config, targets []model.Target) *model.Report
}

func newFlagSet(o *Options, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("chera", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&o.Preset, "preset", "", "preset to run (see --list-presets); default: dev")
	fs.BoolVar(&o.JSON, "json", false, "print machine-readable JSON")
	fs.BoolVar(&o.Markdown, "markdown", false, "print a Markdown report ready to paste into an issue")
	fs.BoolVar(&o.Verbose, "verbose", false, "show every test and its raw evidence")
	fs.BoolVar(&o.Verbose, "v", false, "shorthand for --verbose")
	fs.DurationVar(&o.Timeout, "timeout", 5*time.Second, "timeout for each network operation")
	fs.StringVar(&o.Proxy, "proxy", "", "send TCP connections through a proxy (http://host:port or socks5://host:port)")
	fs.StringVar(&o.Resolver, "resolver", "", "DNS resolver to test instead of the system one (IP[:port]), or a DoH URL to trust as reference")
	fs.BoolVar(&o.Speed, "speed", false, "also measure handshake time and throughput to detect throttling")
	fs.StringVar(&o.Lang, "lang", "", "output language: en or fa (default: from locale)")
	fs.IntVar(&o.Concurrency, "concurrency", 8, "number of targets checked in parallel")
	fs.BoolVar(&o.NoColor, "no-color", false, "disable colors (NO_COLOR is also honoured)")
	fs.BoolVar(&o.ListPresets, "list-presets", false, "list presets and exit")
	fs.StringVar(&o.PresetsFile, "presets", "", "extra presets YAML file")
	fs.StringVar(&o.SignaturesFile, "signatures", "", "extra signatures YAML file")
	fs.BoolVar(&o.Version, "version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprint(errOut, `chera - explain why a service is unreachable

Usage:
  chera [flags] [host|url ...]

Examples:
  chera                      run the default developer preset
  chera github.com           diagnose one host
  chera --preset ai          run the AI APIs preset
  chera --markdown pypi.org  produce a report for a GitHub issue

Flags:
`)
		fs.PrintDefaults()
	}
	return fs
}

// ParseArgs parses flags and positional targets. Flags may appear before or
// after targets.
func ParseArgs(args []string, errOut io.Writer) (*Options, error) {
	o := &Options{}
	fs := newFlagSet(o, errOut)
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		o.Targets = append(o.Targets, rest[0])
		rest = rest[1:]
	}
	if o.JSON && o.Markdown {
		return nil, errors.New("--json and --markdown cannot be combined")
	}
	if o.Timeout <= 0 {
		return nil, errors.New("--timeout must be positive")
	}
	if o.Concurrency < 1 || o.Concurrency > 64 {
		return nil, errors.New("--concurrency must be between 1 and 64")
	}
	if o.Preset != "" && len(o.Targets) > 0 {
		return nil, errors.New("give either --preset or hosts, not both")
	}
	return o, nil
}

// ParseTarget turns a command-line argument (host or URL) into a target,
// reusing preset metadata for well-known hosts.
func ParseTarget(arg string, set *presets.Set) (model.Target, error) {
	arg = strings.TrimSpace(arg)
	var t model.Target
	if strings.Contains(arg, "://") {
		u, err := url.Parse(arg)
		if err != nil || u.Hostname() == "" {
			return t, fmt.Errorf("invalid URL %q", arg)
		}
		if u.Scheme != "https" {
			return t, fmt.Errorf("only https URLs are supported: %q", arg)
		}
		if u.Port() != "" && u.Port() != "443" {
			return t, fmt.Errorf("only port 443 is supported: %q", arg)
		}
		t, _ = set.Lookup(u.Hostname())
		t.Host = strings.ToLower(u.Hostname())
		t.URL = arg
		return t, nil
	}
	host := strings.ToLower(strings.TrimSuffix(arg, "."))
	if host == "" || strings.ContainsAny(host, " /:@?#") {
		return t, fmt.Errorf("invalid host %q", arg)
	}
	if known, ok := set.Lookup(host); ok {
		return known, nil
	}
	return model.Target{Host: host}, nil
}

// Main runs the command and returns the process exit code.
func Main(args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = os.Getenv
	}
	opts, err := ParseArgs(args, env.Err)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		fmt.Fprintln(env.Err, "chera:", err)
		return ExitUsage
	}
	if opts.Version {
		fmt.Fprintln(env.Out, "chera", Version())
		return ExitOK
	}

	lang := i18n.Detect(env.Getenv)
	if opts.Lang != "" {
		l, ok := i18n.Parse(opts.Lang)
		if !ok {
			fmt.Fprintf(env.Err, "chera: unsupported language %q (use en or fa)\n", opts.Lang)
			return ExitUsage
		}
		lang = l
	}
	cat := i18n.New(lang)

	set := presets.Builtin()
	sigs := signatures.Builtin()
	if dir, err := os.UserConfigDir(); err == nil && env.Getenv("CHERA_NO_USER_CONFIG") == "" {
		if err := set.MergeFile(filepath.Join(dir, "chera", "presets.yaml"), true); err != nil {
			fmt.Fprintln(env.Err, "chera:", err)
			return ExitUsage
		}
		if err := sigs.MergeFile(filepath.Join(dir, "chera", "signatures.yaml"), true); err != nil {
			fmt.Fprintln(env.Err, "chera:", err)
			return ExitUsage
		}
	}
	if opts.PresetsFile != "" {
		if err := set.MergeFile(opts.PresetsFile, false); err != nil {
			fmt.Fprintln(env.Err, "chera:", err)
			return ExitUsage
		}
	}
	if opts.SignaturesFile != "" {
		if err := sigs.MergeFile(opts.SignaturesFile, false); err != nil {
			fmt.Fprintln(env.Err, "chera:", err)
			return ExitUsage
		}
	}

	if opts.ListPresets {
		for _, name := range set.Names() {
			targets, _ := set.Resolve(name)
			marker := " "
			if name == set.Default {
				marker = "*"
			}
			fmt.Fprintf(env.Out, "%s %-12s %2d targets  %s\n", marker, name, len(targets), set.Presets[name].Description)
		}
		return ExitOK
	}

	var targets []model.Target
	if len(opts.Targets) > 0 {
		for _, a := range opts.Targets {
			t, err := ParseTarget(a, set)
			if err != nil {
				fmt.Fprintln(env.Err, "chera:", err)
				return ExitUsage
			}
			targets = append(targets, t)
		}
	} else {
		name := opts.Preset
		if name == "" {
			name = set.Default
		}
		targets, err = set.Resolve(name)
		if err != nil {
			fmt.Fprintln(env.Err, "chera:", err)
			return ExitUsage
		}
	}
	if len(targets) == 0 {
		fmt.Fprintln(env.Err, "chera:", cat.T("error.no_targets", nil))
		return ExitUsage
	}

	cfg, err := buildConfig(opts, sigs)
	if err != nil {
		fmt.Fprintln(env.Err, "chera:", err)
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	run := env.Run
	if run == nil {
		run = func(ctx context.Context, cfg probe.Config, targets []model.Target) *model.Report {
			return probe.New(cfg).Run(ctx, targets)
		}
	}
	rep := run(ctx, cfg, targets)

	switch {
	case opts.JSON:
		if err := report.JSON(env.Out, rep, cat); err != nil {
			fmt.Fprintln(env.Err, "chera:", err)
			return ExitUsage
		}
	case opts.Markdown:
		report.Markdown(env.Out, rep, cat)
	default:
		color := !opts.NoColor && env.Stdout != nil && report.ColorEnabled(env.Stdout, env.Getenv)
		report.Text(env.Out, rep, cat, report.Options{Color: color, Verbose: opts.Verbose})
	}

	for _, t := range rep.Targets {
		if t.Verdict != model.OK {
			return ExitProblems
		}
	}
	return ExitOK
}

func buildConfig(opts *Options, sigs *signatures.Set) (probe.Config, error) {
	cfg := probe.Config{
		Timeout:     opts.Timeout,
		Concurrency: opts.Concurrency,
		Signatures:  sigs,
		Version:     Version(),
		Speed:       opts.Speed,
	}
	if opts.Proxy != "" {
		u, err := netx.ParseProxy(opts.Proxy)
		if err != nil {
			return cfg, err
		}
		cfg.Dialer = netx.Proxied(u, opts.Timeout)
		cfg.ProxyInUse = true
	} else {
		cfg.Dialer = netx.Direct(opts.Timeout)
	}
	if err := probe.ApplyDefaults(&cfg, opts.Resolver); err != nil {
		return cfg, err
	}
	return cfg, nil
}

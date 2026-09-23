package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/presets"
	"github.com/assaabriiii/chera/internal/probe"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		check   func(*Options) bool
		wantErr string
	}{
		{"defaults", nil, func(o *Options) bool { return o.Timeout == 5*time.Second && o.Concurrency == 8 && len(o.Targets) == 0 }, ""},
		{"host then flags", []string{"github.com", "--json", "--timeout", "2s"}, func(o *Options) bool {
			return o.JSON && o.Timeout == 2*time.Second && len(o.Targets) == 1 && o.Targets[0] == "github.com"
		}, ""},
		{"interspersed", []string{"-v", "a.com", "--speed", "b.com"}, func(o *Options) bool {
			return o.Verbose && o.Speed && strings.Join(o.Targets, ",") == "a.com,b.com"
		}, ""},
		{"preset", []string{"--preset", "ai"}, func(o *Options) bool { return o.Preset == "ai" }, ""},
		{"json+md", []string{"--json", "--markdown"}, nil, "cannot be combined"},
		{"preset+host", []string{"--preset", "ai", "github.com"}, nil, "either --preset or hosts"},
		{"bad timeout", []string{"--timeout", "0s"}, nil, "positive"},
		{"bad concurrency", []string{"--concurrency", "0"}, nil, "between 1 and 64"},
		{"unknown flag", []string{"--nope"}, nil, "not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := ParseArgs(tt.args, io.Discard)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !tt.check(o) {
				t.Fatalf("unexpected options %+v", o)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	set := presets.Builtin()
	tests := []struct {
		arg, host, url, kind, err string
	}{
		{arg: "github.com", host: "github.com", url: "https://github.com/robots.txt", kind: "github"},
		{arg: "Example.ORG.", host: "example.org"},
		{arg: "https://pypi.org/simple/pip/", host: "pypi.org", url: "https://pypi.org/simple/pip/", kind: "pypi"},
		{arg: "http://pypi.org/", err: "only https"},
		{arg: "https://a.com:8443/", err: "port 443"},
		{arg: "a b", err: "invalid host"},
		{arg: "a.com:443", err: "invalid host"},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, err := ParseTarget(tt.arg, set)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Host != tt.host || got.URL != tt.url || got.Kind != tt.kind {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func fakeRun(v model.Verdict) func(context.Context, probe.Config, []model.Target) *model.Report {
	return func(_ context.Context, _ probe.Config, targets []model.Target) *model.Report {
		r := &model.Report{Version: "test"}
		for _, t := range targets {
			r.Targets = append(r.Targets, model.TargetReport{Target: t, Verdict: v, Confidence: model.High, Reason: model.Reason{Key: "ok.http"}})
		}
		return r
	}
}

func run(t *testing.T, v model.Verdict, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	env := Env{
		Out: &out, Err: &errOut,
		Getenv: func(k string) string {
			if k == "CHERA_NO_USER_CONFIG" {
				return "1"
			}
			return ""
		},
		Run: fakeRun(v),
	}
	code := Main(args, env)
	return code, out.String(), errOut.String()
}

func TestMainExitCodesAndFormats(t *testing.T) {
	code, out, _ := run(t, model.OK, "github.com")
	if code != ExitOK || !strings.Contains(out, "github.com") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	code, out, _ = run(t, model.SNIFiltered, "--json", "--preset", "python")
	if code != ExitProblems || !strings.Contains(out, `"verdict": "SNI_FILTERED"`) || !strings.Contains(out, "files.pythonhosted.org") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	code, out, _ = run(t, model.OK, "--markdown", "--lang", "fa", "pypi.org")
	if code != ExitOK || !strings.Contains(out, "مقصد") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	code, out, _ = run(t, model.OK)
	if code != ExitOK || !strings.Contains(out, "12 of 12") {
		t.Fatalf("default preset: code=%d out=%s", code, out)
	}
}

func TestMainUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--preset", "nope"},
		{"--lang", "de"},
		{"--proxy", "ftp://x:1"},
		{"--presets", "/does/not/exist.yaml"},
		{"bad host"},
	} {
		code, _, errOut := run(t, model.OK, args...)
		if code != ExitUsage || errOut == "" {
			t.Errorf("%v: code=%d err=%q", args, code, errOut)
		}
	}
}

func TestListPresetsAndVersion(t *testing.T) {
	code, out, _ := run(t, model.OK, "--list-presets")
	if code != ExitOK || !strings.Contains(out, "* dev") || !strings.Contains(out, "huggingface") {
		t.Fatalf("list: %s", out)
	}
	code, out, _ = run(t, model.OK, "--version")
	if code != ExitOK || !strings.HasPrefix(out, "chera ") {
		t.Fatalf("version: %s", out)
	}
}

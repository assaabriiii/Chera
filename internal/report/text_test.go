package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/i18n"
	"github.com/assaabriiii/chera/internal/model"
)

func sampleReport() *model.Report {
	mk := func(host, kind string, v model.Verdict, key string, also ...model.Verdict) model.TargetReport {
		return model.TargetReport{
			Target:     model.Target{Host: host, Kind: kind},
			Verdict:    v,
			Confidence: model.High,
			Reason:     model.Reason{Key: key, Args: map[string]string{"ip": "10.10.34.35", "status": "200"}},
			Also:       also,
			Evidence: []model.Evidence{
				{Layer: "dns", Check: "system", Status: model.Fail, Detail: "10.10.34.35"},
			},
		}
	}
	return &model.Report{
		Version:  "test",
		Duration: 3 * time.Second,
		Local:    model.LocalSummary{Up: true, DefaultRoute: true, VPNInterfaces: []string{"wg0"}},
		Targets: []model.TargetReport{
			mk("github.com", "github", model.SNIFiltered, "tls.sni_reset", model.DNSPoisoned),
			mk("api.github.com", "github", model.SNIFiltered, "tls.sni_reset"),
			mk("pypi.org", "pypi", model.DNSPoisoned, "dns.block_ip"),
			mk("registry.npmjs.org", "npm", model.OK, "ok.http"),
		},
	}
}

func TestSummary(t *testing.T) {
	got := Summary(sampleReport(), i18n.New(i18n.EN))
	want := "2 of 4 services blocked by SNI filtering; DNS is poisoned for 1; 1 of 4 services reachable"
	if got != want {
		t.Fatalf("summary:\n got %q\nwant %q", got, want)
	}
	if got := Summary(&model.Report{}, i18n.New(i18n.EN)); got != "No targets were checked." {
		t.Fatalf("empty summary = %q", got)
	}
}

func TestSuggestionsGrouped(t *testing.T) {
	s := Suggestions(sampleReport(), i18n.New(i18n.EN))
	if len(s) != 2 {
		t.Fatalf("got %d suggestion lines: %v", len(s), s)
	}
	if !strings.HasPrefix(s[0], "SNI_FILTERED (github.com, api.github.com):") {
		t.Fatalf("unexpected first line %q", s[0])
	}
	if !strings.Contains(s[1], "PyPI mirror") {
		t.Fatalf("missing pypi hint: %q", s[1])
	}
}

func TestTextPlain(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport(), i18n.New(i18n.EN), Options{})
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Fatal("plain output contains ANSI escapes")
	}
	for _, want := range []string{"TARGET", "github.com", "SNI_FILTERED", "(also: DNS_POISONED)", "Summary:", "wg0", "What to do:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[dns   ]") {
		t.Error("evidence printed without --verbose")
	}
	for _, r := range out {
		if r > 127 {
			t.Fatalf("English plain output should be ASCII, found %q", r)
		}
	}
}

func TestTextVerboseAndColor(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport(), i18n.New(i18n.EN), Options{Color: true, Verbose: true})
	out := buf.String()
	if !strings.Contains(out, "\x1b[31m") || !strings.Contains(out, "[dns   ]") {
		t.Fatalf("expected colors and evidence:\n%s", out)
	}
}

func TestTextPersian(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleReport(), i18n.New(i18n.FA), Options{})
	if !strings.Contains(buf.String(), "مقصد") {
		t.Fatal("persian headers missing")
	}
}

func TestWidth(t *testing.T) {
	const withZWNJ = "\u0645\u06cc\u200c\u0634\u0648\u062f" // "می‌شود"
	if width(withZWNJ) != 5 {
		t.Fatalf("width with ZWNJ = %d", width(withZWNJ))
	}
	if pad("ab", 4) != "ab  " {
		t.Fatal("pad")
	}
}

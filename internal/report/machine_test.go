package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/assaabriiii/chera/internal/i18n"
)

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport(), i18n.New(i18n.EN)); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Summary string         `json:"summary"`
		Counts  map[string]int `json:"counts"`
		Targets []struct {
			Target struct {
				Host string `json:"host"`
			} `json:"target"`
			Verdict     string   `json:"verdict"`
			Confidence  string   `json:"confidence"`
			Also        []string `json:"also"`
			Explanation string   `json:"explanation"`
			Suggestion  string   `json:"suggestion"`
			Reason      struct {
				Key string `json:"key"`
			} `json:"reason"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(got.Targets) != 4 || got.Counts["SNI_FILTERED"] != 2 {
		t.Fatalf("unexpected content: %+v", got)
	}
	first := got.Targets[0]
	if first.Target.Host != "github.com" || first.Verdict != "SNI_FILTERED" || first.Reason.Key != "tls.sni_reset" ||
		len(first.Also) != 1 || first.Explanation == "" || first.Suggestion == "" {
		t.Fatalf("unexpected first target: %+v", first)
	}
}

func TestMarkdown(t *testing.T) {
	var buf bytes.Buffer
	Markdown(&buf, sampleReport(), i18n.New(i18n.EN))
	out := buf.String()
	for _, want := range []string{
		"## Chera network report",
		"| `github.com` | **SNI_FILTERED** | high |",
		"### What to do",
		"<details>",
		"| dns | system | fail | 10.10.34.35 |",
		"VPN interfaces=wg0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("markdown contains ANSI escapes")
	}
}

func TestMdCell(t *testing.T) {
	if got := mdCell("a|b\nc"); got != `a\|b c` {
		t.Fatalf("mdCell = %q", got)
	}
}

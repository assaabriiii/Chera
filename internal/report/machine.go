package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/assaabriiii/chera/internal/i18n"
	"github.com/assaabriiii/chera/internal/model"
)

type jsonTarget struct {
	model.TargetReport
	Explanation string `json:"explanation"`
	Suggestion  string `json:"suggestion"`
	DurationMS  int64  `json:"duration_ms"`
}

type jsonReport struct {
	Version    string                `json:"version"`
	Started    time.Time             `json:"started"`
	DurationMS int64                 `json:"duration_ms"`
	OS         string                `json:"os"`
	Arch       string                `json:"arch"`
	Language   string                `json:"language"`
	Local      model.LocalSummary    `json:"local"`
	Summary    string                `json:"summary"`
	Counts     map[model.Verdict]int `json:"counts"`
	Targets    []jsonTarget          `json:"targets"`
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *model.Report, c *i18n.Catalog) error {
	out := jsonReport{
		Version:    r.Version,
		Started:    r.Started,
		DurationMS: r.Duration.Milliseconds(),
		OS:         r.OS,
		Arch:       r.Arch,
		Language:   string(c.Lang),
		Local:      r.Local,
		Summary:    Summary(r, c),
		Counts:     map[model.Verdict]int{},
		Targets:    make([]jsonTarget, 0, len(r.Targets)),
	}
	for _, t := range r.Targets {
		out.Counts[t.Verdict]++
		if t.Evidence == nil {
			t.Evidence = []model.Evidence{}
		}
		out.Targets = append(out.Targets, jsonTarget{
			TargetReport: t,
			Explanation:  c.Explain(t.Reason),
			Suggestion:   c.Suggest(t.Verdict, t.Target.Kind),
			DurationMS:   t.Duration.Milliseconds(),
		})
	}
	if out.Local.Interfaces == nil {
		out.Local.Interfaces = []string{}
	}
	if out.Local.Reachable == nil {
		out.Local.Reachable = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// Markdown writes a report meant to be pasted into a GitHub issue. It never
// includes local IP addresses.
func Markdown(w io.Writer, r *model.Report, c *i18n.Catalog) {
	fmt.Fprintln(w, "## Chera network report")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- **chera**: `%s` on `%s/%s`\n", r.Version, r.OS, r.Arch)
	fmt.Fprintf(w, "- **date**: %s (took %s)\n", r.Started.Format(time.RFC3339), r.Duration.Round(100*time.Millisecond))
	l := r.Local
	fmt.Fprintf(w, "- **local network**: up=%s, default route=%s, DNS interception=%s\n",
		yesNo(l.Up), yesNo(l.DefaultRoute), yesNo(l.DNSIntercept))
	fmt.Fprintf(w, "- **proxy/VPN**: --proxy=%s, VPN interfaces=%s, proxy env=%s, system proxy=%s\n",
		yesNo(l.ProxyFlag), listOrNone(l.VPNInterfaces), listOrNone(l.ProxyEnv), orNone(l.SystemProxy))
	if len(l.Unreachable) > 0 {
		fmt.Fprintf(w, "- **unreachable baseline hosts**: %s\n", strings.Join(l.Unreachable, ", "))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**%s:** %s\n\n", c.T("label.summary", nil), Summary(r, c))

	fmt.Fprintf(w, "| %s | %s | %s | %s |\n", c.T("label.target", nil), c.T("label.verdict", nil),
		c.T("label.confidence", nil), c.T("label.explanation", nil))
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, t := range r.Targets {
		expl := c.Explain(t.Reason)
		if len(t.Also) > 0 {
			expl += " (" + c.T("label.also", nil) + ": " + joinVerdicts(t.Also) + ")"
		}
		fmt.Fprintf(w, "| `%s` | **%s** | %s | %s |\n", t.Target.Host, t.Verdict, c.Confidence(t.Confidence), mdCell(expl))
	}

	if s := Suggestions(r, c); len(s) > 0 {
		fmt.Fprintf(w, "\n### %s\n\n", c.T("label.suggestions", nil))
		for _, line := range s {
			fmt.Fprintln(w, "- "+line)
		}
	}
	if notes := Notes(r, c); len(notes) > 0 {
		fmt.Fprintln(w)
		for _, n := range notes {
			fmt.Fprintln(w, "> "+n)
		}
	}

	fmt.Fprintf(w, "\n<details>\n<summary>%s</summary>\n\n", c.T("label.evidence", nil))
	for _, t := range r.Targets {
		fmt.Fprintf(w, "#### `%s` - %s (%s)\n\n", t.Target.Host, t.Verdict, c.Confidence(t.Confidence))
		fmt.Fprintln(w, "| Layer | Check | Status | Detail |")
		fmt.Fprintln(w, "|---|---|---|---|")
		for _, e := range t.Evidence {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", e.Layer, mdCell(e.Check), e.Status, mdCell(e.Detail))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "</details>")
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

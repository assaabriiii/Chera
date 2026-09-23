// Package report renders diagnosis results as a terminal table, JSON or a
// Markdown report.
package report

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/assaabriiii/chera/internal/i18n"
	"github.com/assaabriiii/chera/internal/model"
)

// Options control text rendering.
type Options struct {
	Color   bool
	Verbose bool
}

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiMagenta = "\x1b[35m"
)

// ColorEnabled decides whether ANSI colors should be used for f. It honours
// NO_COLOR (https://no-color.org), TERM=dumb, and only colors terminals.
// On Windows, colors are used only in terminals known to support ANSI
// sequences, so classic consoles get clean plain text.
func ColorEnabled(f *os.File, getenv func(string) string) bool {
	if getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return false
	}
	if getenv("FORCE_COLOR") != "" {
		return true
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		return getenv("WT_SESSION") != "" || getenv("ANSICON") != "" ||
			getenv("ConEmuANSI") == "ON" || getenv("TERM") != ""
	}
	return true
}

func verdictColor(v model.Verdict) string {
	switch v {
	case model.OK:
		return ansiGreen
	case model.Inconclusive, model.Throttled, model.UpstreamOutage:
		return ansiYellow
	case model.LocalNetworkDown:
		return ansiMagenta
	}
	return ansiRed
}

// Text writes the human-readable report.
func Text(w io.Writer, r *model.Report, c *i18n.Catalog, opts Options) {
	paint := func(code, s string) string {
		if !opts.Color || code == "" {
			return s
		}
		return code + s + ansiReset
	}

	headers := []string{
		c.T("label.target", nil), c.T("label.verdict", nil),
		c.T("label.confidence", nil), c.T("label.explanation", nil),
	}
	rows := make([][]string, 0, len(r.Targets))
	for _, t := range r.Targets {
		expl := c.Explain(t.Reason)
		if len(t.Also) > 0 {
			expl += " (" + c.T("label.also", nil) + ": " + joinVerdicts(t.Also) + ")"
		}
		rows = append(rows, []string{t.Target.Host, string(t.Verdict), c.Confidence(t.Confidence), expl})
	}

	widths := make([]int, 3)
	for i := range widths {
		widths[i] = width(headers[i])
		for _, row := range rows {
			if n := width(row[i]); n > widths[i] {
				widths[i] = n
			}
		}
	}

	fmt.Fprintln(w)
	line := pad(headers[0], widths[0]) + "  " + pad(headers[1], widths[1]) + "  " +
		pad(headers[2], widths[2]) + "  " + headers[3]
	fmt.Fprintln(w, paint(ansiBold, line))
	for i, row := range rows {
		v := r.Targets[i].Verdict
		fmt.Fprintln(w, pad(row[0], widths[0])+"  "+
			paint(verdictColor(v), pad(row[1], widths[1]))+"  "+
			pad(row[2], widths[2])+"  "+row[3])
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, paint(ansiBold, c.T("label.summary", nil)+":")+" "+Summary(r, c))
	fmt.Fprintln(w, paint(ansiDim, c.T("label.checked", map[string]string{
		"total":    fmt.Sprint(len(r.Targets)),
		"duration": r.Duration.Round(100 * time.Millisecond).String(),
	})))

	for _, note := range Notes(r, c) {
		fmt.Fprintln(w, paint(ansiYellow, "! ")+note)
	}

	if s := Suggestions(r, c); len(s) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, paint(ansiBold, c.T("label.suggestions", nil)+":"))
		for _, line := range s {
			fmt.Fprintln(w, "  - "+line)
		}
	}

	if opts.Verbose {
		for _, t := range r.Targets {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "%s  %s (%s)  %s\n", paint(ansiBold, t.Target.Host),
				paint(verdictColor(t.Verdict), string(t.Verdict)), c.Confidence(t.Confidence),
				t.Duration.Round(time.Millisecond))
			for _, e := range t.Evidence {
				fmt.Fprintf(w, "  [%-6s] %s %-18s %s\n", e.Layer, paint(statusColor(e.Status), pad(string(e.Status), 4)), e.Check, e.Detail)
			}
		}
	}
}

func statusColor(s model.Status) string {
	switch s {
	case model.Pass:
		return ansiGreen
	case model.Fail:
		return ansiRed
	case model.Warn:
		return ansiYellow
	}
	return ansiDim
}

// Summary builds the one-line summary, e.g. "4 of 12 services blocked by
// SNI filtering; DNS is poisoned for 3; 5 of 12 services reachable".
func Summary(r *model.Report, c *i18n.Catalog) string {
	if len(r.Targets) == 0 {
		return c.T("summary.none", nil)
	}
	counts := map[model.Verdict]int{}
	for _, t := range r.Targets {
		counts[t.Verdict]++
	}
	var problems []model.Verdict
	for _, v := range model.AllVerdicts {
		if v != model.OK && counts[v] > 0 {
			problems = append(problems, v)
		}
	}
	sort.SliceStable(problems, func(i, j int) bool { return counts[problems[i]] > counts[problems[j]] })
	total := fmt.Sprint(len(r.Targets))
	var parts []string
	for _, v := range problems {
		parts = append(parts, c.T("summary."+string(v), map[string]string{"n": fmt.Sprint(counts[v]), "total": total}))
	}
	parts = append(parts, c.T("summary.OK", map[string]string{"n": fmt.Sprint(counts[model.OK]), "total": total}))
	return strings.Join(parts, "; ")
}

// Suggestions returns one line per distinct (verdict, remedy) pair among
// the non-OK targets, naming the affected hosts.
func Suggestions(r *model.Report, c *i18n.Catalog) []string {
	type group struct {
		text  string
		v     model.Verdict
		hosts []string
	}
	var groups []*group
	byText := map[string]*group{}
	for _, t := range r.Targets {
		if t.Verdict == model.OK {
			continue
		}
		text := c.Suggest(t.Verdict, t.Target.Kind)
		key := string(t.Verdict) + "\x00" + text
		g, ok := byText[key]
		if !ok {
			g = &group{text: text, v: t.Verdict}
			byText[key] = g
			groups = append(groups, g)
		}
		g.hosts = append(g.hosts, t.Target.Host)
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, fmt.Sprintf("%s (%s): %s", g.v, strings.Join(g.hosts, ", "), g.text))
	}
	return out
}

// Notes returns environment facts that change how results should be read.
func Notes(r *model.Report, c *i18n.Catalog) []string {
	var notes []string
	l := r.Local
	if !l.Up {
		detail := "no default route"
		if l.DefaultRoute {
			detail = "no well-known host reachable"
		}
		notes = append(notes, c.T("label.local_down", map[string]string{"detail": detail}))
	}
	if l.ProxyFlag {
		notes = append(notes, c.T("label.proxy_flag", nil))
	}
	if len(l.VPNInterfaces) > 0 {
		notes = append(notes, c.T("label.vpn", map[string]string{"names": strings.Join(l.VPNInterfaces, ", ")}))
	}
	if len(l.ProxyEnv) > 0 && !l.ProxyFlag {
		notes = append(notes, c.T("label.proxy_env", map[string]string{"names": strings.Join(l.ProxyEnv, ", ")}))
	}
	if l.SystemProxy != "" && !l.ProxyFlag {
		notes = append(notes, c.T("label.proxy_sys", map[string]string{"proxy": l.SystemProxy}))
	}
	if l.DNSIntercept {
		notes = append(notes, c.T("label.dns_hijack", nil))
	}
	return notes
}

func joinVerdicts(vs []model.Verdict) string {
	s := make([]string, len(vs))
	for i, v := range vs {
		s[i] = string(v)
	}
	return strings.Join(s, ", ")
}

// width approximates the display width of s: zero-width joiners and
// combining marks (common in Persian text) take no column.
func width(s string) int {
	n := 0
	for _, r := range s {
		if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		n++
	}
	return n
}

func pad(s string, n int) string {
	if d := n - width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

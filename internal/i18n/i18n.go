// Package i18n provides the user-facing messages in English and Persian.
package i18n

import (
	"os"
	"sort"
	"strings"

	"github.com/assaabriiii/chera/internal/model"
)

// Lang is a supported language code.
type Lang string

// Supported languages.
const (
	EN Lang = "en"
	FA Lang = "fa"
)

// Parse maps a user-supplied language to a supported one.
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == "en" || strings.HasPrefix(s, "en_") || strings.HasPrefix(s, "en-"):
		return EN, true
	case s == "fa" || s == "per" || s == "persian" || s == "farsi" ||
		strings.HasPrefix(s, "fa_") || strings.HasPrefix(s, "fa-"):
		return FA, true
	}
	return EN, false
}

// Detect picks a language from the locale environment variables.
func Detect(getenv func(string) string) Lang {
	if getenv == nil {
		getenv = os.Getenv
	}
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"} {
		val := getenv(v)
		if val == "" {
			continue
		}
		// LANGUAGE may be a colon-separated preference list.
		first := strings.Split(val, ":")[0]
		if l, ok := Parse(first); ok {
			return l
		}
		return EN
	}
	return EN
}

// Catalog translates message keys for one language.
type Catalog struct {
	Lang Lang
	msgs map[string]string
}

// New returns the catalog for lang, falling back to English per key.
func New(lang Lang) *Catalog {
	c := &Catalog{Lang: lang, msgs: map[string]string{}}
	for k, v := range english {
		c.msgs[k] = v
	}
	if lang == FA {
		for k, v := range persian {
			c.msgs[k] = v
		}
	}
	return c
}

// T returns the message for key with {placeholders} replaced from args.
// Unknown keys are returned as-is so a missing translation is visible but
// harmless.
func (c *Catalog) T(key string, args map[string]string) string {
	msg, ok := c.msgs[key]
	if !ok {
		msg = key
	}
	if len(args) == 0 {
		return msg
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(args)*2)
	for _, k := range keys {
		pairs = append(pairs, "{"+k+"}", args[k])
	}
	return strings.NewReplacer(pairs...).Replace(msg)
}

// Explain renders a verdict reason.
func (c *Catalog) Explain(r model.Reason) string {
	return c.T("reason."+r.Key, r.Args)
}

// Suggest returns the practical next step for a verdict, including a
// remedy hint for the target's ecosystem where one applies.
func (c *Catalog) Suggest(v model.Verdict, kind string) string {
	s := c.T("suggest."+string(v), nil)
	if kind != "" && blocking(v) {
		if hint, ok := c.msgs["hint."+kind]; ok {
			s += " " + hint
		}
	}
	return s
}

// Confidence renders a confidence level.
func (c *Catalog) Confidence(conf model.Confidence) string {
	return c.T("confidence."+string(conf), nil)
}

// Keys returns every key known in the given language table; used by tests.
func Keys(lang Lang) []string {
	src := english
	if lang == FA {
		src = persian
	}
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// blocking reports whether a verdict means the network path to the service
// is blocked, so ecosystem mirrors are a useful remedy.
func blocking(v model.Verdict) bool {
	switch v {
	case model.DNSPoisoned, model.DNSIntercepted, model.IPBlocked,
		model.ConnectionReset, model.SNIFiltered, model.BlockPage,
		model.Throttled, model.ProviderGeoBlock:
		return true
	}
	return false
}

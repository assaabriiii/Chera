package i18n

import (
	"strings"
	"testing"

	"github.com/assaabriiii/chera/internal/model"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		env  map[string]string
		want Lang
	}{
		{map[string]string{}, EN},
		{map[string]string{"LANG": "fa_IR.UTF-8"}, FA},
		{map[string]string{"LANG": "en_US.UTF-8"}, EN},
		{map[string]string{"LC_ALL": "fa_IR", "LANG": "en_US"}, FA},
		{map[string]string{"LC_ALL": "C", "LANG": "fa_IR"}, EN},
		{map[string]string{"LANGUAGE": "fa:en"}, FA},
	}
	for _, tt := range tests {
		got := Detect(func(k string) string { return tt.env[k] })
		if got != tt.want {
			t.Errorf("Detect(%v) = %s, want %s", tt.env, got, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]Lang{"fa": FA, "FA": FA, "persian": FA, "en": EN, "en-GB": EN} {
		got, ok := Parse(in)
		if !ok || got != want {
			t.Errorf("Parse(%q) = %s,%v", in, got, ok)
		}
	}
	if _, ok := Parse("de"); ok {
		t.Error("Parse(de) should fail")
	}
}

func TestPersianCoversEnglish(t *testing.T) {
	fa := map[string]bool{}
	for _, k := range Keys(FA) {
		fa[k] = true
	}
	for _, k := range Keys(EN) {
		if !fa[k] {
			t.Errorf("missing Persian translation for %q", k)
		}
	}
	for k := range fa {
		if _, ok := english[k]; !ok {
			t.Errorf("Persian key %q has no English source", k)
		}
	}
}

func TestPlaceholdersMatch(t *testing.T) {
	for k, en := range english {
		fa, ok := persian[k]
		if !ok {
			continue
		}
		for _, ph := range placeholders(en) {
			if !strings.Contains(fa, ph) {
				t.Errorf("%s: Persian text lacks placeholder %s", k, ph)
			}
		}
	}
}

func TestEveryVerdictHasMessages(t *testing.T) {
	c := New(EN)
	for _, v := range model.AllVerdicts {
		for _, key := range []string{"summary." + string(v), "suggest." + string(v)} {
			if c.T(key, nil) == key {
				t.Errorf("missing message %s", key)
			}
		}
	}
}

func TestTAndSuggest(t *testing.T) {
	c := New(EN)
	got := c.Explain(model.Reason{Key: "dns.block_ip", Args: map[string]string{"ip": "10.10.34.35"}})
	if !strings.Contains(got, "10.10.34.35") {
		t.Fatalf("placeholder not replaced: %q", got)
	}
	if s := c.Suggest(model.SNIFiltered, "pypi"); !strings.Contains(s, "PyPI mirror") {
		t.Fatalf("missing ecosystem hint: %q", s)
	}
	if s := c.Suggest(model.OK, "pypi"); strings.Contains(s, "mirror") {
		t.Fatalf("OK should not carry a hint: %q", s)
	}
	if got := c.T("does.not.exist", nil); got != "does.not.exist" {
		t.Fatalf("unknown key = %q", got)
	}
	if got := New(FA).T("label.target", nil); got != "مقصد" {
		t.Fatalf("fa label = %q", got)
	}
}

func placeholders(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "{")
		if i < 0 {
			return out
		}
		j := strings.Index(s[i:], "}")
		if j < 0 {
			return out
		}
		out = append(out, s[i:i+j+1])
		s = s[i+j+1:]
	}
}

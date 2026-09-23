package presets

import (
	"strings"
	"testing"
)

func TestBuiltinResolves(t *testing.T) {
	s := Builtin()
	if s.Default != "dev" {
		t.Fatalf("default preset = %q, want dev", s.Default)
	}
	for _, name := range s.Names() {
		targets, err := s.Resolve(name)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		if len(targets) == 0 {
			t.Fatalf("preset %s is empty", name)
		}
	}
}

func TestResolveCounts(t *testing.T) {
	s := Builtin()
	tests := []struct {
		preset string
		want   int
	}{
		{"github", 5},
		{"python", 2},
		{"docker", 3},
		{"ai", 3},
		{"dev", 12},
		{"all", 18},
	}
	for _, tt := range tests {
		t.Run(tt.preset, func(t *testing.T) {
			got, err := s.Resolve(tt.preset)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.want {
				t.Fatalf("got %d targets, want %d", len(got), tt.want)
			}
		})
	}
}

func TestMergeAndDedup(t *testing.T) {
	s := Builtin()
	f, err := Parse([]byte(`
presets:
  mine:
    include: [python, extra]
  extra:
    targets:
      - host: pypi.org
      - host: example.org
        url: https://example.org/health
`))
	if err != nil {
		t.Fatal(err)
	}
	s.Merge(f)
	got, err := s.Resolve("mine")
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, tg := range got {
		hosts = append(hosts, tg.Host)
	}
	if strings.Join(hosts, ",") != "pypi.org,files.pythonhosted.org,example.org" {
		t.Fatalf("unexpected hosts %v", hosts)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"both", "presets:\n  x:\n    include: [a]\n    targets: [{host: a}]\n", "either targets or include"},
		{"nohost", "presets:\n  x:\n    targets: [{url: https://a/}]\n", "no host"},
		{"unknown field", "presets:\n  x:\n    hosts: [a]\n", "not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestCycleAndUnknown(t *testing.T) {
	s := &Set{Presets: map[string]Preset{
		"a": {Include: []string{"b"}},
		"b": {Include: []string{"a"}},
	}}
	if _, err := s.Resolve("a"); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
	if _, err := s.Resolve("zzz"); err == nil || !strings.Contains(err.Error(), "unknown preset") {
		t.Fatalf("expected unknown preset error, got %v", err)
	}
}

func TestLookup(t *testing.T) {
	s := Builtin()
	tg, ok := s.Lookup("PyPI.org")
	if !ok || tg.Kind != "pypi" {
		t.Fatalf("lookup pypi.org = %+v, %v", tg, ok)
	}
	if _, ok := s.Lookup("unknown.example"); ok {
		t.Fatal("unexpected match")
	}
}

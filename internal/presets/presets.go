// Package presets loads the named target lists chera ships with and merges
// user-defined presets on top of them.
package presets

import (
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/assaabriiii/chera/internal/model"
)

//go:embed presets.yaml
var builtin []byte

// Preset is a named group of targets. Either Targets or Include is set.
type Preset struct {
	Description string         `yaml:"description"`
	Targets     []model.Target `yaml:"targets"`
	Include     []string       `yaml:"include"`
}

// File is the on-disk format of a presets file.
type File struct {
	Default string            `yaml:"default"`
	Presets map[string]Preset `yaml:"presets"`
}

// Set is a merged collection of presets.
type Set struct {
	Default string
	Presets map[string]Preset
}

// Parse decodes a presets file.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse presets: %w", err)
	}
	for name, p := range f.Presets {
		if len(p.Targets) > 0 && len(p.Include) > 0 {
			return nil, fmt.Errorf("preset %q: use either targets or include, not both", name)
		}
		for i, t := range p.Targets {
			if strings.TrimSpace(t.Host) == "" {
				return nil, fmt.Errorf("preset %q: target %d has no host", name, i+1)
			}
		}
	}
	return &f, nil
}

// Builtin returns the embedded presets.
func Builtin() *Set {
	f, err := Parse(builtin)
	if err != nil {
		panic("embedded presets are invalid: " + err.Error())
	}
	return &Set{Default: f.Default, Presets: f.Presets}
}

// Merge adds or replaces presets from f. A preset with the same name as an
// existing one replaces it.
func (s *Set) Merge(f *File) {
	if f.Default != "" {
		s.Default = f.Default
	}
	for name, p := range f.Presets {
		s.Presets[name] = p
	}
}

// MergeFile loads path and merges it. A missing file is not an error when
// optional is true.
func (s *Set) MergeFile(path string, optional bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil
		}
		return err
	}
	f, err := Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	s.Merge(f)
	return nil
}

// Names returns preset names in sorted order.
func (s *Set) Names() []string {
	names := make([]string, 0, len(s.Presets))
	for n := range s.Presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Resolve expands a preset (following includes) into a de-duplicated list
// of targets, preserving order.
func (s *Set) Resolve(name string) ([]model.Target, error) {
	var out []model.Target
	seen := map[string]bool{}
	var walk func(n string, stack []string) error
	walk = func(n string, stack []string) error {
		for _, s := range stack {
			if s == n {
				return fmt.Errorf("preset include cycle: %s -> %s", strings.Join(stack, " -> "), n)
			}
		}
		p, ok := s.Presets[n]
		if !ok {
			return fmt.Errorf("unknown preset %q (available: %s)", n, strings.Join(s.Names(), ", "))
		}
		for _, inc := range p.Include {
			if err := walk(inc, append(stack, n)); err != nil {
				return err
			}
		}
		for _, t := range p.Targets {
			key := strings.ToLower(t.Host)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, t)
		}
		return nil
	}
	if err := walk(name, nil); err != nil {
		return nil, err
	}
	return out, nil
}

// Lookup returns the preset definition for a known host so that a target
// given on the command line still gets its URL, status page and kind.
func (s *Set) Lookup(host string) (model.Target, bool) {
	host = strings.ToLower(host)
	for _, name := range s.Names() {
		for _, t := range s.Presets[name].Targets {
			if strings.ToLower(t.Host) == host {
				return t, true
			}
		}
	}
	return model.Target{}, false
}

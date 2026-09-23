// Package signatures holds the lists used to recognise filtering: injected
// DNS addresses, block pages, provider geo-block responses and TLS
// inspection products.
package signatures

import (
	_ "embed"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed signatures.yaml
var builtin []byte

// BlockPage describes a government or ISP block page.
type BlockPage struct {
	Name         string   `yaml:"name"`
	URLContains  []string `yaml:"url_contains"`
	BodyContains []string `yaml:"body_contains"`
}

// GeoBlock describes a provider-side region block response.
type GeoBlock struct {
	Name         string   `yaml:"name"`
	HostSuffix   string   `yaml:"host_suffix"`
	Status       []int    `yaml:"status"`
	BodyContains []string `yaml:"body_contains"`
}

// File is the on-disk format.
type File struct {
	BlockIPs            []string    `yaml:"block_ips"`
	BlockPages          []BlockPage `yaml:"block_pages"`
	GeoBlocks           []GeoBlock  `yaml:"geo_blocks"`
	InterceptionIssuers []string    `yaml:"interception_issuers"`
}

// Set is a parsed, ready-to-use signature collection.
type Set struct {
	BlockIPs            map[netip.Addr]bool
	BlockPages          []BlockPage
	GeoBlocks           []GeoBlock
	InterceptionIssuers []string
}

// Parse decodes a signatures file.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse signatures: %w", err)
	}
	for _, ip := range f.BlockIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			return nil, fmt.Errorf("block_ips: invalid address %q", ip)
		}
	}
	for _, b := range f.BlockPages {
		if b.Name == "" {
			return nil, fmt.Errorf("block_pages: entry without name")
		}
	}
	for _, g := range f.GeoBlocks {
		if g.Name == "" || len(g.BodyContains) == 0 {
			return nil, fmt.Errorf("geo_blocks: %q needs a name and body_contains", g.Name)
		}
	}
	return &f, nil
}

// New returns an empty set.
func New() *Set {
	return &Set{BlockIPs: map[netip.Addr]bool{}}
}

// Builtin returns the embedded signatures.
func Builtin() *Set {
	f, err := Parse(builtin)
	if err != nil {
		panic("embedded signatures are invalid: " + err.Error())
	}
	s := New()
	s.Merge(f)
	return s
}

// Merge appends the entries of f.
func (s *Set) Merge(f *File) {
	for _, ip := range f.BlockIPs {
		s.BlockIPs[netip.MustParseAddr(ip).Unmap()] = true
	}
	s.BlockPages = append(s.BlockPages, f.BlockPages...)
	s.GeoBlocks = append(s.GeoBlocks, f.GeoBlocks...)
	s.InterceptionIssuers = append(s.InterceptionIssuers, f.InterceptionIssuers...)
}

// MergeFile loads and merges path. A missing file is ignored when optional.
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

// IsBlockIP reports whether addr is a known block-page address.
func (s *Set) IsBlockIP(addr netip.Addr) bool {
	return s.BlockIPs[addr.Unmap()]
}

// MatchBlockPage returns the name of the block page matched by a redirect
// location or a response body, or "".
func (s *Set) MatchBlockPage(location, body string) string {
	loc := strings.ToLower(location)
	b := strings.ToLower(body)
	for _, p := range s.BlockPages {
		if loc != "" && containsAny(loc, p.URLContains) {
			return p.Name
		}
		if b != "" && containsAny(b, p.BodyContains) {
			return p.Name
		}
	}
	return ""
}

// MatchGeoBlock returns the name of the geo-block signature matched by a
// response, or "".
func (s *Set) MatchGeoBlock(host string, status int, body string) string {
	host = strings.ToLower(host)
	b := strings.ToLower(body)
	for _, g := range s.GeoBlocks {
		if g.HostSuffix != "" && !hasHostSuffix(host, strings.ToLower(g.HostSuffix)) {
			continue
		}
		if len(g.Status) > 0 && !containsInt(g.Status, status) {
			continue
		}
		if containsAny(b, g.BodyContains) {
			return g.Name
		}
	}
	return ""
}

// MatchInterceptionIssuer returns the matched TLS inspection product for a
// certificate issuer string, or "".
func (s *Set) MatchInterceptionIssuer(issuer string) string {
	is := strings.ToLower(issuer)
	for _, name := range s.InterceptionIssuers {
		if strings.Contains(is, strings.ToLower(name)) {
			return name
		}
	}
	return ""
}

func hasHostSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(s, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

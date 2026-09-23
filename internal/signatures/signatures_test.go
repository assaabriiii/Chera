package signatures

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBlockIPs(t *testing.T) {
	s := Builtin()
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.10.34.34", true},
		{"10.10.34.35", true},
		{"10.10.34.36", true},
		{"::ffff:10.10.34.35", true},
		{"10.10.34.37", false},
		{"140.82.121.4", false},
	}
	for _, tt := range tests {
		if got := s.IsBlockIP(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("IsBlockIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestMatchBlockPage(t *testing.T) {
	s := Builtin()
	tests := []struct {
		name, location, body, want string
	}{
		{"redirect", "http://10.10.34.34/?type=Invalid%20Site", "", "iran-peyvandha"},
		{"iframe", "", `<html><iframe src="http://10.10.34.34?type=Invalid Site&policy=MainPolicy"></iframe></html>`, "iran-peyvandha"},
		{"portal", "", "Visit https://peyvandha.ir for more", "iran-peyvandha"},
		{"clean", "https://github.com/login", "<html>GitHub</html>", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.MatchBlockPage(tt.location, tt.body); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchGeoBlock(t *testing.T) {
	s := Builtin()
	tests := []struct {
		name   string
		host   string
		status int
		body   string
		want   string
	}{
		{"openai", "api.openai.com", 403, `{"error":{"code":"unsupported_country_region_territory"}}`, "openai-unsupported-region"},
		{"openai wrong status", "api.openai.com", 401, `unsupported_country_region_territory`, ""},
		{"gemini", "generativelanguage.googleapis.com", 400, `User location is not supported for the API use.`, "google-user-location"},
		{"docker", "registry-1.docker.io", 403, `Since Docker is a US company, we must comply with US export control regulations.`, "docker-export-control"},
		{"cloudflare", "example.com", 403, `error code: 1009`, "cloudflare-country-ban"},
		{"plain 403", "api.github.com", 403, `rate limit exceeded`, ""},
		{"host suffix only", "notopenai.com", 403, `unsupported_country_region_territory`, "generic-trade-restriction"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.MatchGeoBlock(tt.host, tt.status, tt.body); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInterceptionIssuer(t *testing.T) {
	s := Builtin()
	if got := s.MatchInterceptionIssuer("CN=FortiGate CA,O=Fortinet"); got == "" {
		t.Fatal("expected Fortinet match")
	}
	if got := s.MatchInterceptionIssuer("CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1,O=DigiCert Inc"); got != "" {
		t.Fatalf("unexpected match %q", got)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ yaml, want string }{
		{"block_ips: [not-an-ip]", "invalid address"},
		{"block_pages: [{url_contains: [x]}]", "without name"},
		{"geo_blocks: [{name: x}]", "body_contains"},
	}
	for _, tt := range tests {
		_, err := Parse([]byte(tt.yaml))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Parse(%q) err = %v, want %q", tt.yaml, err, tt.want)
		}
	}
}

func TestMergeAppends(t *testing.T) {
	s := Builtin()
	f, err := Parse([]byte("block_ips: [192.0.2.7]\nblock_pages: [{name: test, body_contains: [blocked-by-test]}]"))
	if err != nil {
		t.Fatal(err)
	}
	s.Merge(f)
	if !s.IsBlockIP(netip.MustParseAddr("192.0.2.7")) || !s.IsBlockIP(netip.MustParseAddr("10.10.34.34")) {
		t.Fatal("merge lost entries")
	}
	if s.MatchBlockPage("", "this is blocked-by-test") != "test" {
		t.Fatal("custom block page not matched")
	}
}

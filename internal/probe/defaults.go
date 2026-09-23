package probe

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/localnet"
)

// Public resolvers queried over plain UDP. Their answers are compared with
// DoH to spot on-path DNS injection.
var defaultPublicUDP = []string{"1.1.1.1:53", "8.8.8.8:53"}

// DoH resolvers used as the trusted reference. Each is dialed at a fixed
// bootstrap IP so that looking up the DoH server itself does not go
// through the resolver under test.
var defaultDoH = []struct{ label, url, bootstrap string }{
	{"doh:cloudflare", "https://cloudflare-dns.com/dns-query", "1.1.1.1:443"},
	{"doh:google", "https://dns.google/dns-query", "8.8.8.8:443"},
	{"doh:quad9", "https://dns.quad9.net/dns-query", "9.9.9.9:443"},
}

// DefaultInterceptionProbe is an address in TEST-NET-2 (RFC 5737). No DNS
// server can legitimately answer there, so any reply to a query sent to it
// means DNS traffic is being redirected on the path.
const DefaultInterceptionProbe = "198.51.100.53:53"

// ApplyDefaults fills cfg with the real-world resolvers. resolver is the
// value of --resolver: an IP[:port] replaces the system resolver as the
// resolver under test, an https:// URL is added as the first DoH reference.
func ApplyDefaults(cfg *Config, resolver string) error {
	fillDefaults(cfg)
	rs := dnscheck.Resolvers{System: &dnscheck.System{}}
	for _, a := range defaultPublicUDP {
		rs.Public = append(rs.Public, &dnscheck.UDP{Label: "udp:" + strings.TrimSuffix(a, ":53"), Addr: a})
	}
	if resolver != "" {
		if strings.HasPrefix(resolver, "https://") {
			u, err := url.Parse(resolver)
			if err != nil || u.Host == "" {
				return fmt.Errorf("invalid --resolver URL %q", resolver)
			}
			rs.DoH = append(rs.DoH, dnscheck.NewDoH("doh:"+u.Host, resolver, "", cfg.Dialer, cfg.RootCAs, cfg.Timeout))
		} else {
			addr, err := resolverAddr(resolver)
			if err != nil {
				return err
			}
			rs.System = &dnscheck.UDP{Label: "resolver:" + addr, Addr: addr}
		}
	}
	for _, d := range defaultDoH {
		rs.DoH = append(rs.DoH, dnscheck.NewDoH(d.label, d.url, d.bootstrap, cfg.Dialer, cfg.RootCAs, cfg.Timeout))
	}
	cfg.Resolvers = rs
	if cfg.InterceptionProbe == "" {
		cfg.InterceptionProbe = DefaultInterceptionProbe
	}
	if cfg.Local == nil {
		cfg.Local = &localnet.Config{Dialer: cfg.Dialer, Timeout: cfg.Timeout, Baseline: localnet.DefaultBaseline}
	}
	return nil
}

func resolverAddr(s string) (string, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return net.JoinHostPort(a.String(), "53"), nil
	}
	return "", fmt.Errorf("invalid --resolver %q: use an IP address, IP:port, or an https:// DoH URL", s)
}

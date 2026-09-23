package probe

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/httpcheck"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/speed"
	"github.com/assaabriiii/chera/internal/tcpcheck"
	"github.com/assaabriiii/chera/internal/tlscheck"
)

// evidence turns the raw layer results into the list shown by --verbose
// and in JSON/Markdown reports.
func evidence(st *run) []model.Evidence {
	var ev []model.Evidence
	add := func(layer, check string, s model.Status, format string, args ...any) {
		ev = append(ev, model.Evidence{Layer: layer, Check: check, Status: s, Detail: fmt.Sprintf(format, args...)})
	}

	if l := st.shared.local; l != nil {
		down, reason := l.Down()
		if down {
			add("local", "connectivity", model.Fail, "local network down: %s", reason)
		} else {
			add("local", "connectivity", model.Pass, "default route present")
		}
		for _, p := range l.Baseline {
			if p.OK {
				add("local", "baseline "+p.Addr, model.Pass, "connected in %s", ms(p.Duration))
			} else {
				add("local", "baseline "+p.Addr, model.Warn, "%s", netx.Short(p.Err))
			}
		}
		if v := l.VPNNames(); len(v) > 0 {
			add("local", "vpn", model.Info, "VPN-like interfaces: %s", strings.Join(v, ", "))
		}
		if len(l.ProxyEnv) > 0 {
			add("local", "proxy env", model.Info, "set: %s", strings.Join(l.ProxyEnv, ", "))
		}
		if l.SystemProxy != "" {
			add("local", "system proxy", model.Info, "%s", l.SystemProxy)
		}
	}

	if ic := st.shared.intercept; ic != nil {
		if ic.Detected {
			add("dns", "interception", model.Fail, "query to non-DNS address %s was answered (%s)", ic.Probe, addrList(ic.Addrs))
		} else {
			add("dns", "interception", model.Pass, "no answer from non-DNS address %s", ic.Probe)
		}
	}

	if st.resolved {
		a := st.analysis
		answers := append([]dnscheck.Answer{st.dns.System}, st.dns.Public...)
		answers = append(answers, st.dns.DoH...)
		for _, ans := range answers {
			if ans.Resolver == "" {
				continue
			}
			if !ans.OK() {
				add("dns", ans.Resolver, model.Fail, "%s after %s", dnsErr(ans), ms(ans.Duration))
				continue
			}
			status := model.Pass
			for _, ip := range ans.Addrs {
				if contains(a.BlockIPs, ip) || contains(a.Bogons, ip) {
					status = model.Fail
				}
			}
			if ans.Kind == dnscheck.KindSystem && len(a.Suspects) > 0 {
				status = model.Warn
			}
			add("dns", ans.Resolver, status, "%s in %s", addrList(ans.Addrs), ms(ans.Duration))
		}
		switch {
		case len(a.BlockIPs) > 0:
			add("dns", "analysis", model.Fail, "answer contains known block-page address %s", addrList(a.BlockIPs))
		case len(a.Bogons) > 0:
			add("dns", "analysis", model.Fail, "answer contains private/reserved address %s while reference is public", addrList(a.Bogons))
		case len(a.Suspects) > 0:
			add("dns", "analysis", model.Warn, "system answer %s differs from reference %s", addrList(a.Suspects), addrList(a.Reference))
		case a.Unresolvable:
			add("dns", "analysis", model.Fail, "no resolver returned an address")
		default:
			add("dns", "analysis", model.Pass, "reference addresses from %s: %s", a.ReferenceKind, addrList(a.Reference))
		}
		if a.InjectedPublic {
			add("dns", "injection", model.Fail, "plain UDP queries to public resolvers get rewritten answers; DoH does not")
		}
		if v := st.verify; v != nil {
			if v.Outcome == tlscheck.OK {
				add("dns", "verify system IP", model.Pass, "%s serves a valid certificate for %s (CDN variation)", addrList(a.Suspects[:1]), st.target.Host)
			} else {
				add("dns", "verify system IP", model.Fail, "%s: %s", addrList(a.Suspects[:1]), handshakeDetail(*v))
			}
		}
	}

	for _, t := range st.tcp {
		if t.Outcome == tcpcheck.OK {
			add("tcp", t.Addr.String(), model.Pass, "connected in %s", ms(t.Duration))
		} else {
			add("tcp", t.Addr.String(), model.Fail, "%s after %s (%s)", t.Outcome, ms(t.Duration), netx.Short(t.Err))
		}
	}
	if st.resolved && len(st.analysis.Reference) > 0 && len(st.tcp) == 0 {
		add("tcp", "connect", model.Skip, "no reference address to connect to")
	}

	if t := st.tls; t != nil {
		for _, h := range []*tlscheck.Handshake{&t.Real, t.Neutral, t.NoSNI} {
			if h == nil {
				continue
			}
			name := "sni=" + h.SNI
			if h.SNI == "" {
				name = "no sni"
			}
			status := model.Fail
			switch {
			case h.Outcome == tlscheck.OK:
				status = model.Pass
			case h != &t.Real && h.Reached():
				status = model.Pass
			}
			add("tls", name, status, "%s", handshakeDetail(*h))
		}
		if t.SNIFiltered() {
			add("tls", "analysis", model.Fail, "real SNI blocked while the same address answers other names")
		}
	}

	if h := st.http; h != nil {
		switch h.Class {
		case httpcheck.Failed:
			add("http", "GET "+h.URL, model.Fail, "%s after %s (%s)", h.ErrKind, ms(h.Duration), netx.Short(h.Err))
		case httpcheck.OK:
			add("http", "GET "+h.URL, model.Pass, "HTTP %d in %s%s", h.Status, ms(h.Duration), locationSuffix(h.Location))
		default:
			sig := ""
			if h.Signature != "" {
				sig = ", signature " + h.Signature
			}
			add("http", "GET "+h.URL, model.Fail, "HTTP %d classified as %s%s%s", h.Status, h.Class, sig, locationSuffix(h.Location))
		}
		if h.Snippet != "" && h.Class != httpcheck.OK {
			add("http", "body", model.Info, "%s", h.Snippet)
		}
	}

	if sp := st.speed; sp != nil {
		for _, m := range []struct {
			name string
			m    speed.Measurement
		}{{"target", sp.Target}, {"baseline", sp.Baseline}} {
			if m.m.Err != nil {
				add("speed", m.name, model.Warn, "%s: %s", m.m.URL, netx.Short(m.m.Err))
				continue
			}
			add("speed", m.name, model.Info, "HTTP %d, %d bytes in %s (%s), TLS handshake %s",
				m.m.Status, m.m.Bytes, ms(m.m.Duration), speed.FormatRate(m.m.Rate()), ms(m.m.Handshake))
		}
		if sp.Throttled {
			add("speed", "analysis", model.Fail, "severe %s degradation compared with the baseline", sp.Kind)
		} else {
			add("speed", "analysis", model.Pass, "no severe degradation detected")
		}
	}

	if o := st.outage; o != nil {
		switch {
		case o.Err != nil:
			add("outage", "status page", model.Warn, "%s: %s (inconclusive)", o.URL, netx.Short(o.Err))
		case o.Confirmed():
			add("outage", "status page", model.Fail, "%s: %s (%s)", o.URL, o.Description, o.Indicator)
		default:
			add("outage", "status page", model.Pass, "%s: %s", o.URL, o.Description)
		}
	}
	return ev
}

func locationSuffix(loc string) string {
	if loc == "" {
		return ""
	}
	return " -> " + loc
}

func handshakeDetail(h tlscheck.Handshake) string {
	switch h.Outcome {
	case tlscheck.OK:
		return fmt.Sprintf("%s in %s, issuer %q", h.Version, ms(h.Duration), h.Issuer)
	case tlscheck.CertInvalid:
		return fmt.Sprintf("certificate invalid (%s), issuer %q: %s", h.CertProblem, h.Issuer, netx.Short(h.Err))
	case tlscheck.Alert:
		return fmt.Sprintf("server sent TLS alert: %v", h.Err)
	}
	return fmt.Sprintf("%s after %s (%s)", h.Outcome, ms(h.Duration), netx.Short(h.Err))
}

func dnsErr(a dnscheck.Answer) string {
	switch a.FailureKind() {
	case "nxdomain":
		return "NXDOMAIN"
	case "noanswer":
		return "no addresses"
	case "timeout":
		return "timeout"
	}
	return netx.Short(a.Err)
}

func addrList(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return "-"
	}
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

func contains(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func ms(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}

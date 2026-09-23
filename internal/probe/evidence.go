package probe

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
)

// evidence turns the raw layer results into the list shown by --verbose
// and in JSON/Markdown reports.
func evidence(st *run) []model.Evidence {
	var ev []model.Evidence
	add := func(layer, check string, s model.Status, format string, args ...any) {
		ev = append(ev, model.Evidence{Layer: layer, Check: check, Status: s, Detail: fmt.Sprintf(format, args...)})
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
	}
	return ev
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

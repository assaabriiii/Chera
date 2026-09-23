// Package verdict turns the evidence gathered by the layers into exactly
// one primary verdict per target, with a confidence level and a reason.
//
// The engine walks the layers in order. A problem found on the verified
// network path (TCP, TLS, HTTP) wins over a DNS problem, because fixing DNS
// alone would not make the service work; the DNS problem is then reported
// as a secondary finding.
package verdict

import (
	"fmt"
	"net/netip"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/httpcheck"
	"github.com/assaabriiii/chera/internal/localnet"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/signatures"
	"github.com/assaabriiii/chera/internal/tcpcheck"
	"github.com/assaabriiii/chera/internal/tlscheck"
)

// Input is everything measured for one target. Nil pointers mean the
// layer did not run.
type Input struct {
	Local      *localnet.Result
	Intercept  *dnscheck.Interception
	DNS        dnscheck.Analysis
	TCP        []tcpcheck.Result
	TLS        *tlscheck.Result
	Verify     *tlscheck.Handshake
	HTTP       *httpcheck.Result
	Signatures *signatures.Set
}

// Decision is the engine's output.
type Decision struct {
	Verdict    model.Verdict
	Confidence model.Confidence
	Reason     model.Reason
	Also       []model.Verdict
}

func decide(v model.Verdict, c model.Confidence, key string, args ...string) *Decision {
	r := model.Reason{Key: key}
	if len(args) > 0 {
		r.Args = map[string]string{}
		for i := 0; i+1 < len(args); i += 2 {
			r.Args[args[i]] = args[i+1]
		}
	}
	return &Decision{Verdict: v, Confidence: c, Reason: r}
}

// Decide returns the verdict for one target.
func Decide(in Input) Decision {
	sum := tcpcheck.Summarize(in.TCP)

	if in.Local != nil && sum.Working == nil {
		if down, why := in.Local.Down(); down {
			conf := model.High
			if why == localnet.DownUnreachable {
				conf = model.Medium
			}
			return *decide(model.LocalNetworkDown, conf, "local."+why)
		}
	}

	dnsD := dnsDecision(in)
	pathD := pathDecision(in, sum)

	switch {
	case pathD == nil && dnsD != nil:
		return *dnsD
	case pathD == nil && in.DNS.Unresolvable:
		return *decide(model.Inconclusive, model.Low, "dns.unresolvable")
	case pathD == nil:
		return *decide(model.Inconclusive, model.Low, "inconclusive")
	case dnsD == nil:
		return *pathD
	case pathD.Verdict == model.OK || pathD.Verdict == model.Inconclusive:
		// The path to the real service is fine (or unclear), so the DNS
		// problem is what breaks it for applications.
		return *dnsD
	default:
		pathD.Also = append(pathD.Also, dnsD.Verdict)
		return *pathD
	}
}

// dnsDecision reports a DNS problem, or nil when DNS looks healthy.
func dnsDecision(in Input) *Decision {
	a := in.DNS
	intercepted := in.Intercept != nil && in.Intercept.Detected
	mismatch := len(a.Suspects) > 0 && in.Verify != nil && in.Verify.Outcome != tlscheck.OK

	if a.Poisoned() || mismatch {
		ip := first(a.BlockIPs, a.Bogons, a.Suspects)
		switch {
		case intercepted || a.InjectedPublic:
			return decide(model.DNSIntercepted, model.High, "dns.intercepted", "ip", ip)
		case len(a.BlockIPs) > 0:
			return decide(model.DNSPoisoned, model.High, "dns.block_ip", "ip", ip)
		case len(a.Bogons) > 0:
			return decide(model.DNSPoisoned, model.High, "dns.bogon", "ip", ip)
		default:
			return decide(model.DNSPoisoned, model.Medium, "dns.mismatch", "ip", ip)
		}
	}
	switch a.SystemFailure {
	case "":
		return nil
	case "nxdomain", "noanswer":
		return decide(model.DNSPoisoned, model.Medium, "dns.nxdomain")
	default:
		return decide(model.DNSPoisoned, model.Low, "dns.failed", "error", a.SystemFailure)
	}
}

// pathDecision judges the connection to the verified addresses. It returns
// nil when no connection was attempted.
func pathDecision(in Input, sum tcpcheck.Summary) *Decision {
	if len(in.TCP) == 0 {
		return nil
	}
	if sum.Working == nil {
		ip := in.TCP[0].Addr.Addr().String()
		baselineOK := in.Local != nil && in.Local.AnyBaseline()
		switch {
		case sum.AnyRejected:
			return decide(model.ConnectionReset, model.Medium, "tcp.reset", "ip", ip)
		case sum.AllTimeout:
			conf := model.Medium
			if baselineOK {
				conf = model.High
			}
			return decide(model.IPBlocked, conf, "tcp.timeout", "ip", ip)
		case sum.AllUnreachable:
			return decide(model.IPBlocked, model.Medium, "tcp.unreachable", "ip", ip)
		}
		return decide(model.Inconclusive, model.Low, "inconclusive")
	}
	ip := sum.Working.Addr.Addr().String()

	if in.TLS == nil {
		return decide(model.OK, model.Low, "ok.tls")
	}
	real := in.TLS.Real
	switch {
	case in.TLS.SNIFiltered():
		key := "tls.sni_reset"
		if real.Outcome == tlscheck.Timeout {
			key = "tls.sni_timeout"
		}
		return decide(model.SNIFiltered, model.High, key)
	case real.Outcome == tlscheck.Timeout:
		return decide(model.IPBlocked, model.Medium, "tls.timeout", "ip", ip)
	case real.Blocked():
		return decide(model.ConnectionReset, model.Medium, "tls.reset", "ip", ip)
	case real.Outcome == tlscheck.Alert:
		return decide(model.Inconclusive, model.Low, "tls.alert", "error", netx.Short(real.Err))
	case real.Outcome != tlscheck.OK && real.Outcome != tlscheck.CertInvalid:
		return decide(model.Inconclusive, model.Low, "inconclusive")
	}

	h := in.HTTP
	if h != nil && h.Class == httpcheck.BlockPage {
		return decide(model.BlockPage, model.High, "http.block_page", "signature", h.Signature)
	}
	if real.Outcome == tlscheck.CertInvalid {
		issuer := real.IssuerName
		switch real.CertProblem {
		case tlscheck.CertUnknownAuthority:
			return decide(model.TLSIntercepted, model.High, "tls.untrusted", "issuer", issuer)
		case tlscheck.CertHostname:
			return decide(model.TLSIntercepted, model.Medium, "tls.hostname", "issuer", issuer)
		case tlscheck.CertExpired:
			return decide(model.TLSIntercepted, model.Low, "tls.expired")
		default:
			return decide(model.TLSIntercepted, model.Medium, "tls.untrusted", "issuer", issuer)
		}
	}
	if in.Signatures != nil {
		if name := in.Signatures.MatchInterceptionIssuer(real.Issuer); name != "" {
			return decide(model.TLSIntercepted, model.Medium, "tls.middlebox", "issuer", name)
		}
	}
	if h == nil {
		return decide(model.OK, model.Medium, "ok.tls")
	}

	status := fmt.Sprint(h.Status)
	switch h.Class {
	case httpcheck.GeoBlock:
		return decide(model.ProviderGeoBlock, model.High, "http.geo_block", "status", status, "signature", h.Signature)
	case httpcheck.Legal:
		return decide(model.ProviderGeoBlock, model.Medium, "http.451")
	case httpcheck.ServerError:
		return decide(model.UpstreamOutage, model.Medium, "http.5xx", "status", status)
	case httpcheck.Failed:
		switch h.ErrKind {
		case netx.KindReset, netx.KindEOF:
			return decide(model.ConnectionReset, model.Medium, "http.reset")
		case netx.KindTimeout:
			return decide(model.Inconclusive, model.Low, "http.timeout")
		}
		return decide(model.Inconclusive, model.Low, "http.error", "error", netx.Short(h.Err))
	}
	return decide(model.OK, model.High, "ok.http", "status", status)
}

func first(lists ...[]netip.Addr) string {
	for _, l := range lists {
		if len(l) > 0 {
			return l[0].String()
		}
	}
	return ""
}

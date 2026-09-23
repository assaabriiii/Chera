package verdict

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/assaabriiii/chera/internal/dnscheck"
	"github.com/assaabriiii/chera/internal/httpcheck"
	"github.com/assaabriiii/chera/internal/localnet"
	"github.com/assaabriiii/chera/internal/model"
	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/signatures"
	"github.com/assaabriiii/chera/internal/tcpcheck"
	"github.com/assaabriiii/chera/internal/testutil"
	"github.com/assaabriiii/chera/internal/tlscheck"
)

var (
	addr    = netip.MustParseAddrPort("140.82.121.4:443")
	up      = &localnet.Result{Interfaces: []localnet.Iface{{Name: "eth0", Up: true, HasAddr: true}}, DefaultRoute: true, Baseline: []localnet.Probe{{OK: true}}}
	cleanNS = dnscheck.Analysis{Reference: testutil.Addrs("140.82.121.4"), ReferenceKind: dnscheck.KindDoH}
	tcpOK   = []tcpcheck.Result{{Addr: addr, Outcome: tcpcheck.OK}}
	tlsOK   = &tlscheck.Result{Real: tlscheck.Handshake{Outcome: tlscheck.OK, Issuer: "CN=DigiCert,O=DigiCert Inc", IssuerName: "DigiCert Inc"}}
	http200 = &httpcheck.Result{Status: 200, Class: httpcheck.OK}
)

func healthy() Input {
	return Input{Local: up, DNS: cleanNS, TCP: tcpOK, TLS: tlsOK, HTTP: http200, Signatures: signatures.Builtin()}
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input)
		want   model.Verdict
		conf   model.Confidence
		reason string
		also   []model.Verdict
	}{
		{"ok", func(in *Input) {}, model.OK, model.High, "ok.http", nil},
		{"ok without http", func(in *Input) { in.HTTP = nil }, model.OK, model.Medium, "ok.tls", nil},
		{"local no route", func(in *Input) {
			in.Local = &localnet.Result{Interfaces: up.Interfaces}
			in.TCP = []tcpcheck.Result{{Addr: addr, Outcome: tcpcheck.Unreachable}}
		}, model.LocalNetworkDown, model.High, "local.no_route", nil},
		{"local unreachable", func(in *Input) {
			in.Local = &localnet.Result{Interfaces: up.Interfaces, DefaultRoute: true, Baseline: []localnet.Probe{{}}}
			in.TCP = []tcpcheck.Result{{Addr: addr, Outcome: tcpcheck.Timeout}}
		}, model.LocalNetworkDown, model.Medium, "local.unreachable", nil},
		{"baseline down but target works is not local down", func(in *Input) {
			in.Local = &localnet.Result{Interfaces: up.Interfaces, DefaultRoute: true, Baseline: []localnet.Probe{{}}}
		}, model.OK, model.High, "ok.http", nil},
		{"dns block ip", func(in *Input) {
			in.DNS.BlockIPs = testutil.Addrs("10.10.34.35")
		}, model.DNSPoisoned, model.High, "dns.block_ip", nil},
		{"dns bogon", func(in *Input) {
			in.DNS.Bogons = testutil.Addrs("192.168.1.1")
		}, model.DNSPoisoned, model.High, "dns.bogon", nil},
		{"dns mismatch verified bad", func(in *Input) {
			in.DNS.Suspects = testutil.Addrs("31.13.64.1")
			in.Verify = &tlscheck.Handshake{Outcome: tlscheck.CertInvalid}
		}, model.DNSPoisoned, model.Medium, "dns.mismatch", nil},
		{"dns mismatch cdn ok", func(in *Input) {
			in.DNS.Suspects = testutil.Addrs("140.82.121.3")
			in.Verify = &tlscheck.Handshake{Outcome: tlscheck.OK}
		}, model.OK, model.High, "ok.http", nil},
		{"dns nxdomain", func(in *Input) { in.DNS.SystemFailure = "nxdomain" }, model.DNSPoisoned, model.Medium, "dns.nxdomain", nil},
		{"dns timeout", func(in *Input) { in.DNS.SystemFailure = "timeout" }, model.DNSPoisoned, model.Low, "dns.failed", nil},
		{"dns intercepted", func(in *Input) {
			in.DNS.BlockIPs = testutil.Addrs("10.10.34.36")
			in.Intercept = &dnscheck.Interception{Detected: true}
		}, model.DNSIntercepted, model.High, "dns.intercepted", nil},
		{"dns injected on public udp", func(in *Input) {
			in.DNS.BlockIPs = testutil.Addrs("10.10.34.36")
			in.DNS.InjectedPublic = true
		}, model.DNSIntercepted, model.High, "dns.intercepted", nil},
		{"interception alone is not a verdict", func(in *Input) {
			in.Intercept = &dnscheck.Interception{Detected: true}
		}, model.OK, model.High, "ok.http", nil},
		{"dns poisoned only, no reference", func(in *Input) {
			in.DNS = dnscheck.Analysis{BlockIPs: testutil.Addrs("10.10.34.34")}
			in.TCP, in.TLS, in.HTTP = nil, nil, nil
		}, model.DNSPoisoned, model.High, "dns.block_ip", nil},
		{"unresolvable", func(in *Input) {
			in.DNS = dnscheck.Analysis{Unresolvable: true}
			in.TCP, in.TLS, in.HTTP = nil, nil, nil
		}, model.Inconclusive, model.Low, "dns.unresolvable", nil},
		{"ip blocked", func(in *Input) {
			in.TCP = []tcpcheck.Result{{Addr: addr, Outcome: tcpcheck.Timeout}, {Addr: addr, Outcome: tcpcheck.Timeout}}
			in.TLS, in.HTTP = nil, nil
		}, model.IPBlocked, model.High, "tcp.timeout", nil},
		{"ip blocked plus dns poisoned", func(in *Input) {
			in.DNS.BlockIPs = testutil.Addrs("10.10.34.35")
			in.TCP = []tcpcheck.Result{{Addr: addr, Outcome: tcpcheck.Timeout}}
			in.TLS, in.HTTP = nil, nil
		}, model.IPBlocked, model.High, "tcp.timeout", []model.Verdict{model.DNSPoisoned}},
		{"tcp reset", func(in *Input) {
			in.TCP = []tcpcheck.Result{{Addr: addr, Outcome: tcpcheck.Refused}}
			in.TLS, in.HTTP = nil, nil
		}, model.ConnectionReset, model.Medium, "tcp.reset", nil},
		{"sni reset", func(in *Input) {
			in.TLS = &tlscheck.Result{
				Real:    tlscheck.Handshake{Outcome: tlscheck.Reset},
				Neutral: &tlscheck.Handshake{Outcome: tlscheck.OK},
				NoSNI:   &tlscheck.Handshake{Outcome: tlscheck.Alert},
			}
			in.HTTP = nil
		}, model.SNIFiltered, model.High, "tls.sni_reset", nil},
		{"sni timeout with dns poisoning", func(in *Input) {
			in.DNS.BlockIPs = testutil.Addrs("10.10.34.35")
			in.TLS = &tlscheck.Result{
				Real:    tlscheck.Handshake{Outcome: tlscheck.Timeout},
				Neutral: &tlscheck.Handshake{Outcome: tlscheck.OK},
				NoSNI:   &tlscheck.Handshake{Outcome: tlscheck.OK},
			}
			in.HTTP = nil
		}, model.SNIFiltered, model.High, "tls.sni_timeout", []model.Verdict{model.DNSPoisoned}},
		{"tls reset for any sni", func(in *Input) {
			in.TLS = &tlscheck.Result{
				Real:    tlscheck.Handshake{Outcome: tlscheck.Reset},
				Neutral: &tlscheck.Handshake{Outcome: tlscheck.Reset},
				NoSNI:   &tlscheck.Handshake{Outcome: tlscheck.Reset},
			}
			in.HTTP = nil
		}, model.ConnectionReset, model.Medium, "tls.reset", nil},
		{"tls timeout for any sni", func(in *Input) {
			in.TLS = &tlscheck.Result{
				Real:    tlscheck.Handshake{Outcome: tlscheck.Timeout},
				Neutral: &tlscheck.Handshake{Outcome: tlscheck.Timeout},
				NoSNI:   &tlscheck.Handshake{Outcome: tlscheck.Timeout},
			}
			in.HTTP = nil
		}, model.IPBlocked, model.Medium, "tls.timeout", nil},
		{"tls alert", func(in *Input) {
			in.TLS = &tlscheck.Result{Real: tlscheck.Handshake{Outcome: tlscheck.Alert, Err: errors.New("remote error: tls: handshake failure")}}
			in.HTTP = nil
		}, model.Inconclusive, model.Low, "tls.alert", nil},
		{"untrusted cert", func(in *Input) {
			in.TLS = &tlscheck.Result{Real: tlscheck.Handshake{Outcome: tlscheck.CertInvalid, CertProblem: tlscheck.CertUnknownAuthority, IssuerName: "Evil"}}
		}, model.TLSIntercepted, model.High, "tls.untrusted", nil},
		{"hostname mismatch", func(in *Input) {
			in.TLS = &tlscheck.Result{Real: tlscheck.Handshake{Outcome: tlscheck.CertInvalid, CertProblem: tlscheck.CertHostname}}
		}, model.TLSIntercepted, model.Medium, "tls.hostname", nil},
		{"expired", func(in *Input) {
			in.TLS = &tlscheck.Result{Real: tlscheck.Handshake{Outcome: tlscheck.CertInvalid, CertProblem: tlscheck.CertExpired}}
		}, model.TLSIntercepted, model.Low, "tls.expired", nil},
		{"middlebox issuer", func(in *Input) {
			in.TLS = &tlscheck.Result{Real: tlscheck.Handshake{Outcome: tlscheck.OK, Issuer: "CN=FortiGate CA,O=Fortinet"}}
		}, model.TLSIntercepted, model.Medium, "tls.middlebox", nil},
		{"block page beats interception", func(in *Input) {
			in.TLS = &tlscheck.Result{Real: tlscheck.Handshake{Outcome: tlscheck.CertInvalid, CertProblem: tlscheck.CertUnknownAuthority}}
			in.HTTP = &httpcheck.Result{Status: 302, Class: httpcheck.BlockPage, Signature: "iran-peyvandha"}
		}, model.BlockPage, model.High, "http.block_page", nil},
		{"geo block", func(in *Input) {
			in.HTTP = &httpcheck.Result{Status: 403, Class: httpcheck.GeoBlock, Signature: "openai-unsupported-region"}
		}, model.ProviderGeoBlock, model.High, "http.geo_block", nil},
		{"451", func(in *Input) { in.HTTP = &httpcheck.Result{Status: 451, Class: httpcheck.Legal} }, model.ProviderGeoBlock, model.Medium, "http.451", nil},
		{"5xx", func(in *Input) { in.HTTP = &httpcheck.Result{Status: 503, Class: httpcheck.ServerError} }, model.UpstreamOutage, model.Medium, "http.5xx", nil},
		{"http reset", func(in *Input) {
			in.HTTP = &httpcheck.Result{Class: httpcheck.Failed, ErrKind: netx.KindReset}
		}, model.ConnectionReset, model.Medium, "http.reset", nil},
		{"http timeout", func(in *Input) {
			in.HTTP = &httpcheck.Result{Class: httpcheck.Failed, ErrKind: netx.KindTimeout, Err: context.DeadlineExceeded}
		}, model.Inconclusive, model.Low, "http.timeout", nil},
		{"http timeout with dns problem prefers dns", func(in *Input) {
			in.DNS.BlockIPs = testutil.Addrs("10.10.34.35")
			in.HTTP = &httpcheck.Result{Class: httpcheck.Failed, ErrKind: netx.KindTimeout, Err: context.DeadlineExceeded}
		}, model.DNSPoisoned, model.High, "dns.block_ip", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := healthy()
			tt.mutate(&in)
			d := Decide(in)
			if d.Verdict != tt.want || d.Confidence != tt.conf || d.Reason.Key != tt.reason {
				t.Fatalf("Decide = %s/%s/%s, want %s/%s/%s", d.Verdict, d.Confidence, d.Reason.Key, tt.want, tt.conf, tt.reason)
			}
			if len(d.Also) != len(tt.also) {
				t.Fatalf("Also = %v, want %v", d.Also, tt.also)
			}
			for i := range tt.also {
				if d.Also[i] != tt.also[i] {
					t.Fatalf("Also = %v, want %v", d.Also, tt.also)
				}
			}
		})
	}
}

func TestReasonArgs(t *testing.T) {
	in := healthy()
	in.DNS.BlockIPs = testutil.Addrs("10.10.34.35")
	if d := Decide(in); d.Reason.Args["ip"] != "10.10.34.35" {
		t.Fatalf("args = %v", d.Reason.Args)
	}
}

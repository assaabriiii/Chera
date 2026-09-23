// Package testutil provides fake network services for tests: DNS servers,
// DoH endpoints, certificate authorities and TLS servers that misbehave in
// the ways filtering middleboxes do.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/dnswire"
)

// Answers maps a lower-case host name to the addresses to return. A host
// that is missing gets NXDOMAIN.
type Answers map[string][]netip.Addr

// Addrs is a helper to build address lists.
func Addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func (a Answers) respond(query []byte) []byte {
	q, err := dnswire.ParseQuestion(query)
	if err != nil {
		return nil
	}
	addrs, ok := a[strings.ToLower(q.Name)]
	rcode := dnswire.RCodeSuccess
	if !ok {
		rcode = dnswire.RCodeNXDomain
	}
	msg, err := dnswire.Answer(q, rcode, addrs)
	if err != nil {
		return nil
	}
	return msg
}

// DNSServer is a fake plain-UDP DNS server.
type DNSServer struct {
	Addr    string
	Queries atomic.Int64
	conn    net.PacketConn
}

// NewDNSServer starts a UDP DNS server on 127.0.0.1 answering from answers.
func NewDNSServer(t testing.TB, answers Answers) *DNSServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &DNSServer{Addr: pc.LocalAddr().String(), conn: pc}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			s.Queries.Add(1)
			if resp := answers.respond(buf[:n]); resp != nil {
				pc.WriteTo(resp, from)
			}
		}
	}()
	return s
}

// DoHHandler returns an RFC 8484 POST handler answering from answers.
func DoHHandler(answers Answers) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		resp := answers.respond(body)
		if resp == nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(resp)
	})
}

// ClosedAddr returns a 127.0.0.1 address with nothing listening on it.
func ClosedAddr(t testing.TB, network string) string {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		pc.Close()
		return addr
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// CA is a throwaway certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Pool *x509.CertPool
}

// NewCA creates a CA whose issuer organisation is org.
func NewCA(t testing.TB, org string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: org + " Root", Organization: []string{org}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: key, Pool: pool}
}

// Leaf issues a server certificate for the given DNS names and IPs.
func (ca *CA) Leaf(t testing.TB, names ...string) tls.Certificate {
	t.Helper()
	return ca.LeafValidity(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), names...)
}

// LeafValidity issues a certificate with an explicit validity window.
func (ca *CA) LeafValidity(t testing.TB, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

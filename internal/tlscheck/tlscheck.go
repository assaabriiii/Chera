// Package tlscheck performs TLS handshakes with different server names
// (SNI) to tell SNI-based filtering apart from IP blocking, and validates
// certificates to spot TLS interception.
package tlscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
)

// Outcome of a handshake.
type Outcome string

// Handshake outcomes.
const (
	OK            Outcome = "ok"
	CertInvalid   Outcome = "cert_invalid"
	Alert         Outcome = "alert"
	Reset         Outcome = "reset"
	Timeout       Outcome = "timeout"
	EOF           Outcome = "eof"
	ConnectFailed Outcome = "connect_failed"
	Error         Outcome = "error"
)

// Certificate problems.
const (
	CertUnknownAuthority = "unknown_authority"
	CertHostname         = "hostname"
	CertExpired          = "expired"
	CertOther            = "other"
)

// DefaultNeutralSNI is the server name used to test whether filtering
// depends on the name. It must be a name that is not itself filtered.
const DefaultNeutralSNI = "example.com"

// Handshake is one TLS handshake attempt.
type Handshake struct {
	SNI         string
	Outcome     Outcome
	Err         error
	Duration    time.Duration
	Version     string
	Issuer      string
	Subject     string
	CertProblem string
}

// Reached reports whether the server answered at the TLS level (even with
// an alert or a certificate we do not trust).
func (h Handshake) Reached() bool {
	return h.Outcome == OK || h.Outcome == CertInvalid || h.Outcome == Alert
}

// Blocked reports whether the handshake died on the network after the TCP
// connection was established: reset, dropped or closed.
func (h Handshake) Blocked() bool {
	return h.Outcome == Reset || h.Outcome == Timeout || h.Outcome == EOF
}

// Options configure handshakes.
type Options struct {
	Dialer     netx.Dialer
	Timeout    time.Duration
	RootCAs    *x509.CertPool
	NeutralSNI string
}

// Do performs one handshake to addr with the given SNI ("" sends none).
// When verifyHost is non-empty the certificate chain is validated for it.
func Do(ctx context.Context, o Options, addr, sni, verifyHost string) Handshake {
	h := Handshake{SNI: sni}
	c, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	start := time.Now()
	raw, err := o.Dialer.DialContext(c, "tcp", addr)
	if err != nil {
		h.Duration = time.Since(start)
		h.Outcome, h.Err = ConnectFailed, err
		return h
	}
	defer raw.Close()
	if dl, ok := c.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // verified below so failures can be classified
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	start = time.Now()
	err = conn.HandshakeContext(c)
	h.Duration = time.Since(start)
	if err != nil {
		h.Err = err
		h.Outcome = fromError(err)
		return h
	}
	state := conn.ConnectionState()
	h.Outcome = OK
	h.Version = tls.VersionName(state.Version)
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		h.Issuer = leaf.Issuer.String()
		h.Subject = leaf.Subject.String()
		if verifyHost != "" {
			if err := Verify(state.PeerCertificates, verifyHost, o.RootCAs); err != nil {
				h.Outcome = CertInvalid
				h.Err = err
				h.CertProblem = CertProblem(err)
			}
		}
	}
	return h
}

func fromError(err error) Outcome {
	switch netx.Classify(err) {
	case netx.KindAlert:
		return Alert
	case netx.KindReset, netx.KindRefused:
		return Reset
	case netx.KindTimeout:
		return Timeout
	case netx.KindEOF:
		return EOF
	}
	return Error
}

// Verify validates a presented chain for host.
func Verify(chain []*x509.Certificate, host string, roots *x509.CertPool) error {
	if len(chain) == 0 {
		return errors.New("no certificate presented")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return err
}

// CertProblem classifies a verification error.
func CertProblem(err error) string {
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return CertUnknownAuthority
	case errors.As(err, &he):
		return CertHostname
	case errors.As(err, &ci) && ci.Reason == x509.Expired:
		return CertExpired
	case strings.Contains(err.Error(), "certificate signed by unknown authority"),
		strings.Contains(err.Error(), "not trusted"):
		return CertUnknownAuthority
	}
	return CertOther
}

// Result is the full TLS layer result for one address.
type Result struct {
	Addr    string
	Real    Handshake
	Neutral *Handshake
	NoSNI   *Handshake
}

// SNIFiltered reports whether the real name is blocked while the same
// address completes a handshake with another name or without SNI.
func (r Result) SNIFiltered() bool {
	if !r.Real.Blocked() {
		return false
	}
	return (r.Neutral != nil && r.Neutral.Reached()) || (r.NoSNI != nil && r.NoSNI.Reached())
}

// Check runs the handshake with the real SNI. Only when that fails at the
// network level does it try the neutral SNI and no SNI, to keep the number
// of connections per target small.
func Check(ctx context.Context, o Options, addr, host string) Result {
	if o.NeutralSNI == "" {
		o.NeutralSNI = DefaultNeutralSNI
	}
	res := Result{Addr: addr, Real: Do(ctx, o, addr, host, host)}
	if !res.Real.Blocked() {
		return res
	}
	var wg sync.WaitGroup
	var neutral, none Handshake
	wg.Add(2)
	go func() { defer wg.Done(); neutral = Do(ctx, o, addr, o.NeutralSNI, "") }()
	go func() { defer wg.Done(); none = Do(ctx, o, addr, "", "") }()
	wg.Wait()
	res.Neutral, res.NoSNI = &neutral, &none
	return res
}

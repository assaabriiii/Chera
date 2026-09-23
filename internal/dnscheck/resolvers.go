// Package dnscheck resolves targets through several independent paths
// (system resolver, plain UDP to public resolvers, DNS-over-HTTPS) and
// decides whether the local answers look poisoned or intercepted.
package dnscheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/assaabriiii/chera/internal/dnswire"
	"github.com/assaabriiii/chera/internal/netx"
)

// Kind identifies how a resolver is reached.
type Kind string

// Resolver kinds.
const (
	KindSystem Kind = "system"
	KindUDP    Kind = "udp"
	KindDoH    Kind = "doh"
)

// Errors returned by resolvers.
var (
	ErrNXDomain = errors.New("name does not exist (NXDOMAIN)")
	ErrNoAnswer = errors.New("no IPv4 addresses in answer")
)

// RCodeError is a DNS failure response other than NXDOMAIN.
type RCodeError int

func (e RCodeError) Error() string {
	switch int(e) {
	case dnswire.RCodeServFail:
		return "server failure (SERVFAIL)"
	case dnswire.RCodeRefused:
		return "query refused (REFUSED)"
	}
	return fmt.Sprintf("DNS error code %d", int(e))
}

// Resolver looks up IPv4 addresses for a host.
type Resolver interface {
	Name() string
	Kind() Kind
	Lookup(ctx context.Context, host string) ([]netip.Addr, error)
}

// System uses the operating system's configured resolver.
type System struct {
	R *net.Resolver
}

// Name implements Resolver.
func (s *System) Name() string { return "system" }

// Kind implements Resolver.
func (s *System) Kind() Kind { return KindSystem }

// Lookup implements Resolver.
func (s *System) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	r := s.R
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, ErrNXDomain
		}
		return nil, err
	}
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	if len(addrs) == 0 {
		return nil, ErrNoAnswer
	}
	return addrs, nil
}

// UDP sends plain DNS queries over UDP to one server.
type UDP struct {
	Label string // e.g. "1.1.1.1"
	Addr  string // host:port
}

// Name implements Resolver.
func (u *UDP) Name() string {
	if u.Label != "" {
		return u.Label
	}
	return u.Addr
}

// Kind implements Resolver.
func (u *UDP) Kind() Kind { return KindUDP }

// Lookup implements Resolver.
func (u *UDP) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	resp, err := udpExchange(ctx, u.Addr, host)
	if err != nil {
		return nil, err
	}
	return addrsFrom(resp)
}

func newID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// udpExchange sends one query and returns the first response that matches
// its ID and question. On-path injectors usually answer first, which is
// exactly what applications on this machine would see.
func udpExchange(ctx context.Context, addr, host string) (*dnswire.Response, error) {
	id := newID()
	q, err := dnswire.Query(id, host, dnswire.TypeA)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		resp, err := dnswire.Parse(buf[:n])
		if err != nil || resp.ID != id || !sameName(resp.Question.Name, host) {
			continue
		}
		return resp, nil
	}
}

func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func addrsFrom(resp *dnswire.Response) ([]netip.Addr, error) {
	switch resp.RCode {
	case dnswire.RCodeSuccess:
	case dnswire.RCodeNXDomain:
		return nil, ErrNXDomain
	default:
		return nil, RCodeError(resp.RCode)
	}
	var out []netip.Addr
	for _, a := range resp.Addrs {
		if a.Is4() || a.Is4In6() {
			out = append(out, a.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, ErrNoAnswer
	}
	return out, nil
}

// DoH is a DNS-over-HTTPS (RFC 8484) resolver. The server is reached at a
// fixed bootstrap address so that its own name does not depend on the
// (possibly poisoned) local resolver.
type DoH struct {
	Label  string
	URL    string
	client *http.Client
}

// NewDoH returns a DoH resolver. bootstrap is "ip:port" and may be empty to
// resolve the URL's host normally. roots may be nil for the system pool.
func NewDoH(label, url, bootstrap string, dialer netx.Dialer, roots *x509.CertPool, timeout time.Duration) *DoH {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if bootstrap != "" {
				addr = bootstrap
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &DoH{Label: label, URL: url, client: &http.Client{Transport: tr, Timeout: timeout}}
}

// Name implements Resolver.
func (d *DoH) Name() string {
	if d.Label != "" {
		return d.Label
	}
	return d.URL
}

// Kind implements Resolver.
func (d *DoH) Kind() Kind { return KindDoH }

// Lookup implements Resolver.
func (d *DoH) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	q, err := dnswire.Query(0, host, dnswire.TypeA) // RFC 8484 recommends ID 0
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	msg, err := dnswire.Parse(body)
	if err != nil {
		return nil, err
	}
	return addrsFrom(msg)
}

// CloseIdle releases pooled connections.
func (d *DoH) CloseIdle() { d.client.CloseIdleConnections() }

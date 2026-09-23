// Package netx contains the dialers used by every layer (direct, HTTP
// CONNECT proxy, SOCKS5 proxy) and the classification of network errors
// into the categories the verdict engine reasons about.
package netx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Dialer opens network connections. Layers take a Dialer so tests can swap
// in fakes that simulate blackholes or resets.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Direct returns a plain dialer with the given connect timeout.
func Direct(timeout time.Duration) Dialer {
	return &net.Dialer{Timeout: timeout}
}

// ErrKind is a coarse error category.
type ErrKind string

// Error categories.
const (
	KindNone        ErrKind = ""
	KindTimeout     ErrKind = "timeout"
	KindRefused     ErrKind = "refused"
	KindReset       ErrKind = "reset"
	KindEOF         ErrKind = "eof"
	KindUnreachable ErrKind = "unreachable"
	KindAlert       ErrKind = "tls_alert"
	KindDNS         ErrKind = "dns"
	KindOther       ErrKind = "other"
)

// Classify maps an error to an ErrKind. It uses typed checks first and
// falls back to message matching so it also works for Windows socket
// errors, whose codes do not map onto the POSIX errno values.
func Classify(err error) ErrKind {
	if err == nil {
		return KindNone
	}
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return KindAlert
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		// The peer answered with something that is not TLS (e.g. an
		// injected HTTP response); treat it like a reset of the TLS stream.
		return KindReset
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return KindRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.EPIPE):
		return KindReset
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return KindUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return KindTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return KindEOF
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return KindTimeout
		}
		return KindDNS
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"), strings.Contains(msg, "actively refused"):
		return KindRefused
	case strings.Contains(msg, "reset"), strings.Contains(msg, "forcibly closed"), strings.Contains(msg, "broken pipe"):
		return KindReset
	case strings.Contains(msg, "unreachable"), strings.Contains(msg, "no route"):
		return KindUnreachable
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"), strings.Contains(msg, "deadline exceeded"):
		return KindTimeout
	case strings.Contains(msg, "eof"):
		return KindEOF
	case strings.Contains(msg, "remote error: tls"):
		return KindAlert
	}
	return KindOther
}

// Short returns a compact, single-line version of err for evidence output.
func Short(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	// Drop the noisy "dial tcp 1.2.3.4:443: connect:" prefixes but keep
	// the cause.
	if i := strings.LastIndex(s, ": "); i >= 0 && Classify(err) != KindOther {
		tail := s[i+2:]
		if tail != "" {
			return tail
		}
	}
	return s
}

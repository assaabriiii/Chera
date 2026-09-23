// Package tcpcheck opens TCP connections to a service's addresses and
// classifies how they fail: a timeout usually means the address is
// blackholed, a reset or refusal means something actively rejects it.
package tcpcheck

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
)

// Outcome of a TCP connect.
type Outcome string

// TCP outcomes.
const (
	OK          Outcome = "ok"
	Timeout     Outcome = "timeout"
	Refused     Outcome = "refused"
	Reset       Outcome = "reset"
	Unreachable Outcome = "unreachable"
	Error       Outcome = "error"
)

// Result is one connection attempt.
type Result struct {
	Addr     netip.AddrPort
	Outcome  Outcome
	Err      error
	Duration time.Duration
}

// Rejected reports whether the connection was actively refused or reset.
func (r Result) Rejected() bool { return r.Outcome == Refused || r.Outcome == Reset }

// FromError maps a dial error to an Outcome.
func FromError(err error) Outcome {
	switch netx.Classify(err) {
	case netx.KindNone:
		return OK
	case netx.KindTimeout:
		return Timeout
	case netx.KindRefused:
		return Refused
	case netx.KindReset, netx.KindEOF:
		return Reset
	case netx.KindUnreachable:
		return Unreachable
	}
	return Error
}

// Probe connects to addr once and closes the connection immediately.
func Probe(ctx context.Context, d netx.Dialer, addr netip.AddrPort, timeout time.Duration) Result {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := d.DialContext(c, "tcp", addr.String())
	res := Result{Addr: addr, Duration: time.Since(start), Err: err, Outcome: FromError(err)}
	if conn != nil {
		conn.Close()
	}
	return res
}

// ProbeAll probes the addresses concurrently and returns results in the
// same order.
func ProbeAll(ctx context.Context, d netx.Dialer, addrs []netip.AddrPort, timeout time.Duration) []Result {
	out := make([]Result, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Add(1)
		go func(i int, a netip.AddrPort) {
			defer wg.Done()
			out[i] = Probe(ctx, d, a, timeout)
		}(i, a)
	}
	wg.Wait()
	return out
}

// Summary condenses several results.
type Summary struct {
	// First successful address, if any.
	Working *Result
	// AllTimeout is true when every attempt timed out.
	AllTimeout bool
	// AnyRejected is true when at least one attempt was refused or reset.
	AnyRejected bool
	// AllUnreachable is true when every attempt had no route.
	AllUnreachable bool
}

// Summarize condenses results.
func Summarize(results []Result) Summary {
	var s Summary
	if len(results) == 0 {
		return s
	}
	s.AllTimeout, s.AllUnreachable = true, true
	for i := range results {
		r := &results[i]
		if r.Outcome == OK && s.Working == nil {
			s.Working = r
		}
		if r.Outcome != Timeout {
			s.AllTimeout = false
		}
		if r.Outcome != Unreachable {
			s.AllUnreachable = false
		}
		if r.Rejected() {
			s.AnyRejected = true
		}
	}
	return s
}

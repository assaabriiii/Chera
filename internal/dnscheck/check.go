package dnscheck

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/signatures"
)

// Answer is what one resolver returned.
type Answer struct {
	Resolver string
	Kind     Kind
	Addrs    []netip.Addr
	Err      error
	Duration time.Duration
}

// OK reports whether the resolver returned addresses.
func (a Answer) OK() bool { return a.Err == nil && len(a.Addrs) > 0 }

// FailureKind classifies a failed lookup: "nxdomain", "noanswer",
// "timeout", "refused" or "error".
func (a Answer) FailureKind() string {
	switch {
	case a.Err == nil:
		return ""
	case errors.Is(a.Err, ErrNXDomain):
		return "nxdomain"
	case errors.Is(a.Err, ErrNoAnswer):
		return "noanswer"
	}
	switch netx.Classify(a.Err) {
	case netx.KindTimeout:
		return "timeout"
	case netx.KindRefused:
		return "refused"
	}
	return "error"
}

// Result holds the answers from every resolver for one host.
type Result struct {
	Host   string
	System Answer
	Public []Answer
	DoH    []Answer
}

// Resolvers is the set of resolvers to consult.
type Resolvers struct {
	System Resolver
	Public []Resolver
	DoH    []Resolver
}

// Resolve queries all resolvers concurrently, each bounded by timeout.
func Resolve(ctx context.Context, host string, rs Resolvers, timeout time.Duration) Result {
	res := Result{Host: host, Public: make([]Answer, len(rs.Public)), DoH: make([]Answer, len(rs.DoH))}
	var wg sync.WaitGroup
	lookup := func(r Resolver, out *Answer) {
		defer wg.Done()
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		start := time.Now()
		addrs, err := r.Lookup(c, host)
		*out = Answer{Resolver: r.Name(), Kind: r.Kind(), Addrs: addrs, Err: err, Duration: time.Since(start)}
	}
	if rs.System != nil {
		wg.Add(1)
		go lookup(rs.System, &res.System)
	}
	for i, r := range rs.Public {
		wg.Add(1)
		go lookup(r, &res.Public[i])
	}
	for i, r := range rs.DoH {
		wg.Add(1)
		go lookup(r, &res.DoH[i])
	}
	wg.Wait()
	return res
}

// Analysis is the interpretation of a Result.
type Analysis struct {
	// Reference are the addresses believed to be correct, from DoH when
	// possible.
	Reference []netip.Addr
	// ReferenceKind says where Reference came from ("" if nowhere).
	ReferenceKind Kind
	// BlockIPs are known block-page addresses seen in plain-DNS answers.
	BlockIPs []netip.Addr
	// Bogons are private/reserved addresses returned by plain DNS while the
	// reference addresses are public.
	Bogons []netip.Addr
	// Suspects are system answers that share nothing with the reference.
	// They are not proof of poisoning (CDNs answer differently per
	// location), so the pipeline verifies them with a TLS handshake.
	Suspects []netip.Addr
	// InjectedPublic is true when plain UDP queries to public resolvers got
	// bad answers while DoH did not: someone on the path answers for them.
	InjectedPublic bool
	// SystemFailure is the system resolver's failure kind while the
	// reference resolved fine ("" otherwise).
	SystemFailure string
	// Unresolvable is true when no resolver returned any address.
	Unresolvable bool
}

// Poisoned reports whether the answers alone prove poisoning.
func (a Analysis) Poisoned() bool {
	return len(a.BlockIPs) > 0 || len(a.Bogons) > 0
}

// Analyze compares the answers.
func Analyze(r Result, sigs *signatures.Set) Analysis {
	var a Analysis
	for _, ans := range r.DoH {
		if ans.OK() {
			a.Reference = union(a.Reference, ans.Addrs)
			a.ReferenceKind = KindDoH
		}
	}
	plain := append([]Answer{r.System}, r.Public...)
	if len(a.Reference) == 0 {
		// Without DoH, fall back to clean-looking plain answers, trusting
		// public resolvers over the system one.
		for _, ans := range append(append([]Answer{}, r.Public...), r.System) {
			if ans.OK() && !hasBad(ans.Addrs, sigs) {
				a.Reference = union(a.Reference, ans.Addrs)
				a.ReferenceKind = ans.Kind
				break
			}
		}
	}
	refPublic := len(a.Reference) > 0 && !allBogon(a.Reference)

	for i, ans := range plain {
		if !ans.OK() {
			continue
		}
		bad := false
		for _, ip := range ans.Addrs {
			switch {
			case sigs.IsBlockIP(ip):
				a.BlockIPs = union(a.BlockIPs, []netip.Addr{ip})
				bad = true
			case refPublic && IsBogon(ip):
				a.Bogons = union(a.Bogons, []netip.Addr{ip})
				bad = true
			}
		}
		// plain[0] is the resolver under test; the rest are public
		// resolvers whose answers should never be rewritten.
		if bad && i > 0 && a.ReferenceKind == KindDoH {
			a.InjectedPublic = true
		}
	}

	if r.System.OK() && len(a.Reference) > 0 && !a.Poisoned() && !intersects(r.System.Addrs, a.Reference) {
		a.Suspects = r.System.Addrs
	}
	if !r.System.OK() && r.System.Resolver != "" && len(a.Reference) > 0 {
		a.SystemFailure = r.System.FailureKind()
	}
	if len(a.Reference) == 0 && len(a.BlockIPs) == 0 && len(a.Bogons) == 0 {
		a.Unresolvable = true
	}
	return a
}

var extraBogons = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// IsBogon reports whether addr is private, reserved or otherwise not a
// public unicast address.
func IsBogon(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	for _, p := range extraBogons {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func hasBad(addrs []netip.Addr, sigs *signatures.Set) bool {
	for _, a := range addrs {
		if sigs.IsBlockIP(a) {
			return true
		}
	}
	return false
}

func allBogon(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if !IsBogon(a) {
			return false
		}
	}
	return true
}

func union(a, b []netip.Addr) []netip.Addr {
	for _, x := range b {
		found := false
		for _, y := range a {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			a = append(a, x)
		}
	}
	return a
}

func intersects(a, b []netip.Addr) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// Interception is the result of the DNS hijack test.
type Interception struct {
	// Probe is the address that was queried. It does not run a DNS
	// server, so any answer means port 53 traffic is being redirected.
	Probe    string
	Detected bool
	Addrs    []netip.Addr
	Err      error
}

// CheckInterception sends one query to probe (an address with no DNS
// server) and reports whether anything answered.
func CheckInterception(ctx context.Context, probe string, timeout time.Duration) Interception {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := Interception{Probe: probe}
	resp, err := udpExchange(c, probe, "example.com")
	if err != nil {
		res.Err = err
		return res
	}
	res.Detected = true
	res.Addrs = resp.Addrs
	return res
}

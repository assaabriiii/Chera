package testutil

import (
	"context"
	"net"
	"sync"
)

// FakeDialer dials for real, except that addresses in Blackhole never
// connect (the dial blocks until the context expires, like a dropped SYN)
// and addresses in Redirect are dialed at another address instead.
type FakeDialer struct {
	Blackhole map[string]bool
	Redirect  map[string]string

	mu    sync.Mutex
	Dials []string
}

// DialContext implements netx.Dialer.
func (f *FakeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.Dials = append(f.Dials, addr)
	f.mu.Unlock()
	if f.Blackhole[addr] {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
	}
	if to, ok := f.Redirect[addr]; ok {
		addr = to
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Count returns how many times addr was dialed.
func (f *FakeDialer) Count(addr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.Dials {
		if a == addr {
			n++
		}
	}
	return n
}

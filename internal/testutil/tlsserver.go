package testutil

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TLSOptions controls how a fake TLS server misbehaves.
type TLSOptions struct {
	// ResetSNI lists server names whose ClientHello is answered with a TCP
	// reset, like an SNI-filtering middlebox.
	ResetSNI []string
	// StallSNI lists server names whose handshake is silently dropped until
	// the client gives up.
	StallSNI []string
	// ResetAll resets every handshake regardless of SNI.
	ResetAll bool
	// Addr is the listen address; default 127.0.0.1:0.
	Addr string
}

// ServeTLS starts an HTTPS server with cert and returns its address.
func ServeTLS(t testing.TB, cert tls.Certificate, handler http.Handler, opts TLSOptions) string {
	t.Helper()
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni := strings.ToLower(hello.ServerName)
			if opts.ResetAll || contains(opts.ResetSNI, sni) {
				Reset(hello.Conn)
				return nil, errors.New("reset by test middlebox")
			}
			if contains(opts.StallSNI, sni) {
				select {
				case <-done:
				case <-time.After(30 * time.Second):
				}
				hello.Conn.Close()
				return nil, errors.New("dropped by test middlebox")
			}
			return nil, nil
		},
	}
	srv := &http.Server{Handler: handler, ErrorLog: nil, ReadHeaderTimeout: 5 * time.Second}
	srv.ErrorLog = discardLogger()
	go srv.Serve(tls.NewListener(ln, cfg))
	t.Cleanup(func() {
		close(done)
		srv.Close()
	})
	return ln.Addr().String()
}

// Reset closes c with SO_LINGER 0 so the peer receives a TCP RST.
func Reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.Close()
}

// ServeReset starts a TCP listener that resets every connection right
// after accepting it.
func ServeReset(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Wait for the ClientHello so the reset happens mid-handshake.
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			c.Read(make([]byte, 1))
			Reset(c)
		}
	}()
	return ln.Addr().String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

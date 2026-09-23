package netx

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrKind
	}{
		{"nil", nil, KindNone},
		{"refused", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, KindRefused},
		{"reset", &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, KindReset},
		{"unreachable", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, KindUnreachable},
		{"deadline", context.DeadlineExceeded, KindTimeout},
		{"os deadline", fmt.Errorf("read: %w", os.ErrDeadlineExceeded), KindTimeout},
		{"net timeout", &net.OpError{Op: "dial", Err: timeoutErr{}}, KindTimeout},
		{"eof", fmt.Errorf("handshake: %w", io.EOF), KindEOF},
		{"alert", tls.AlertError(112), KindAlert},
		{"windows reset", errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), KindReset},
		{"windows refused", errors.New("connectex: No connection could be made because the target machine actively refused it."), KindRefused},
		{"dns", &net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}, KindDNS},
		{"other", errors.New("boom"), KindOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Fatalf("Classify(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestShort(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
		Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	if got := Short(err); got != "connection refused" {
		t.Fatalf("Short = %q", got)
	}
	if Short(nil) != "" {
		t.Fatal("Short(nil)")
	}
}

func TestParseProxy(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8080", "socks5://user:pw@localhost:1080", "socks5h://h:1"} {
		if _, err := ParseProxy(ok); err != nil {
			t.Errorf("ParseProxy(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://h:1", "http://nohostport", "::"} {
		if _, err := ParseProxy(bad); err == nil {
			t.Errorf("ParseProxy(%q) should fail", bad)
		}
	}
}

// echoServer accepts one connection and echoes a greeting.
func echoServer(t *testing.T) string {
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
			c.Write([]byte("hello"))
			c.Close()
		}
	}()
	return ln.Addr().String()
}

func TestHTTPConnectProxy(t *testing.T) {
	target := echoServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	gotAuth := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		gotAuth <- req.Header.Get("Proxy-Authorization")
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer up.Close()
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		io.Copy(c, up)
	}()
	u, _ := url.Parse("http://u:p@" + ln.Addr().String())
	conn, err := Proxied(u, time.Second).DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q, %v", buf, err)
	}
	if auth := <-gotAuth; auth != "Basic dTpw" {
		t.Fatalf("auth header = %q", auth)
	}
}

func TestSOCKS5Proxy(t *testing.T) {
	target := echoServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 262)
		io.ReadFull(c, buf[:2])
		io.ReadFull(c, buf[:buf[1]])
		c.Write([]byte{0x05, 0x00})
		io.ReadFull(c, buf[:4])
		var host string
		switch buf[3] {
		case 0x01:
			io.ReadFull(c, buf[:4])
			host = net.IP(buf[:4]).String()
		case 0x03:
			io.ReadFull(c, buf[:1])
			n := int(buf[0])
			io.ReadFull(c, buf[:n])
			host = string(buf[:n])
		}
		io.ReadFull(c, buf[:2])
		port := binary.BigEndian.Uint16(buf[:2])
		up, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
		io.Copy(c, up)
	}()
	u, _ := url.Parse("socks5://" + ln.Addr().String())
	conn, err := Proxied(u, time.Second).DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q, %v", buf, err)
	}
}

// TestHTTPConnectEarlyData covers a proxy whose tunnel delivers data in the
// same read as the CONNECT response.
func TestHTTPConnectEarlyData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		http.ReadRequest(bufio.NewReader(c))
		c.Write([]byte("HTTP/1.1 200 OK\r\n\r\nhello"))
		time.Sleep(100 * time.Millisecond)
	}()
	u, _ := url.Parse("http://" + ln.Addr().String())
	conn, err := Proxied(u, time.Second).DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("read %q, %v", buf, err)
	}
}

func TestProxyRejectsUDP(t *testing.T) {
	u, _ := url.Parse("socks5://127.0.0.1:1")
	if _, err := Proxied(u, time.Second).DialContext(context.Background(), "udp", "1.1.1.1:53"); err == nil {
		t.Fatal("expected error for udp")
	}
}

package netx

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ParseProxy validates a proxy URL. Supported schemes are http and socks5
// (socks5h is accepted as an alias).
func ParseProxy(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch u.Scheme {
	case "http", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http:// or socks5://)", u.Scheme)
	}
	if u.Host == "" || u.Port() == "" {
		return nil, fmt.Errorf("proxy URL needs host:port, got %q", raw)
	}
	return u, nil
}

// Proxied returns a Dialer that tunnels TCP connections through the proxy.
func Proxied(u *url.URL, timeout time.Duration) Dialer {
	return &proxyDialer{u: u, base: &net.Dialer{Timeout: timeout}}
}

type proxyDialer struct {
	u    *url.URL
	base *net.Dialer
}

func (p *proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxy supports only TCP, not %s", network)
	}
	conn, err := p.base.DialContext(ctx, "tcp", p.u.Host)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if p.u.Scheme == "http" {
		var br *bufio.Reader
		br, err = httpConnect(conn, p.u, address)
		if err == nil && br.Buffered() > 0 {
			// The tunnel may already carry data from the far end.
			conn = &bufferedConn{Conn: conn, r: br}
		}
	} else {
		err = socks5Connect(conn, p.u, address)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// bufferedConn returns bytes already read into a bufio.Reader before
// reading from the connection again.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func httpConnect(conn net.Conn, u *url.URL, address string) (*bufio.Reader, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: http.Header{},
	}
	if u.User != nil {
		pass, _ := u.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("proxy CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("proxy CONNECT: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s: %s", address, resp.Status)
	}
	return br, nil
}

func socks5Connect(conn net.Conn, u *url.URL, address string) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %q", portStr)
	}
	methods := []byte{0x00}
	if u.User != nil {
		methods = []byte{0x00, 0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("socks5: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5: %w", err)
	}
	if reply[0] != 0x05 {
		return errors.New("socks5: bad server version")
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		user := u.User.Username()
		pass, _ := u.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("socks5: credentials too long")
		}
		msg := []byte{0x01, byte(len(user))}
		msg = append(msg, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := conn.Write(msg); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
		if reply[1] != 0x00 {
			return errors.New("socks5: authentication failed")
		}
	default:
		return errors.New("socks5: no acceptable authentication method")
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks5: host name too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 connect to %s failed (code %d)", address, head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return fmt.Errorf("socks5 connect: %w", err)
		}
		skip = int(l[0])
	default:
		return errors.New("socks5: bad address type in reply")
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}
	return nil
}

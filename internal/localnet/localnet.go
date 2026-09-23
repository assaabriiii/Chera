// Package localnet checks the machine's own connectivity before any
// service is blamed: interfaces, default route, whether well-known hosts
// are reachable, and whether a proxy or VPN changes what the results mean.
package localnet

import (
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
)

// DefaultBaseline are well-known anycast addresses used to test general
// connectivity. Reaching any one of them means the connection works.
var DefaultBaseline = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}

// Iface is the privacy-safe description of a network interface.
type Iface struct {
	Name    string
	Up      bool
	Loop    bool
	HasAddr bool // has a non-link-local unicast address
	VPN     bool
}

// Probe is one baseline connection attempt.
type Probe struct {
	Addr     string
	OK       bool
	Err      error
	Duration time.Duration
}

// Result is the local network layer's output.
type Result struct {
	Interfaces   []Iface
	DefaultRoute bool
	Baseline     []Probe
	ProxyEnv     []string
	SystemProxy  string
}

// Down reasons.
const (
	DownNoInterface = "no_interface"
	DownNoRoute     = "no_route"
	DownUnreachable = "unreachable"
)

// Down reports whether the local connection is unusable and why.
func (r Result) Down() (bool, string) {
	active := false
	for _, i := range r.Interfaces {
		if i.Up && !i.Loop && i.HasAddr {
			active = true
		}
	}
	if !active && len(r.Interfaces) > 0 {
		return true, DownNoInterface
	}
	if !r.DefaultRoute {
		return true, DownNoRoute
	}
	if len(r.Baseline) > 0 && !r.AnyBaseline() {
		return true, DownUnreachable
	}
	return false, ""
}

// AnyBaseline reports whether at least one baseline host was reachable.
func (r Result) AnyBaseline() bool {
	for _, p := range r.Baseline {
		if p.OK {
			return true
		}
	}
	return false
}

// VPNNames returns the names of active VPN-like interfaces.
func (r Result) VPNNames() []string {
	var out []string
	for _, i := range r.Interfaces {
		if i.VPN && i.Up && i.HasAddr {
			out = append(out, i.Name)
		}
	}
	return out
}

// Config controls the checks. Zero values use the real system.
type Config struct {
	Dialer   netx.Dialer
	Timeout  time.Duration
	Baseline []string
	// Interfaces lists interfaces; default net.Interfaces.
	Interfaces func() ([]Iface, error)
	// Route reports whether a default route exists; default HasDefaultRoute.
	Route func() bool
	// Getenv reads environment variables; default os.Getenv.
	Getenv func(string) string
	// SystemProxy returns the OS proxy setting; default DetectSystemProxy.
	SystemProxy func(ctx context.Context) string
}

// Check runs the local network checks.
func Check(ctx context.Context, cfg Config) Result {
	if cfg.Interfaces == nil {
		cfg.Interfaces = SystemInterfaces
	}
	if cfg.Route == nil {
		cfg.Route = HasDefaultRoute
	}
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.SystemProxy == nil {
		cfg.SystemProxy = DetectSystemProxy
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	var r Result
	r.Interfaces, _ = cfg.Interfaces()
	r.DefaultRoute = cfg.Route()
	r.ProxyEnv = ProxyEnv(cfg.Getenv)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.SystemProxy = cfg.SystemProxy(ctx)
	}()
	if r.DefaultRoute && cfg.Dialer != nil {
		r.Baseline = make([]Probe, len(cfg.Baseline))
		for i, addr := range cfg.Baseline {
			wg.Add(1)
			go func(i int, addr string) {
				defer wg.Done()
				c, cancel := context.WithTimeout(ctx, cfg.Timeout)
				defer cancel()
				start := time.Now()
				conn, err := cfg.Dialer.DialContext(c, "tcp", addr)
				if conn != nil {
					conn.Close()
				}
				r.Baseline[i] = Probe{Addr: addr, OK: err == nil, Err: err, Duration: time.Since(start)}
			}(i, addr)
		}
	}
	wg.Wait()
	return r
}

// SystemInterfaces lists the machine's interfaces without exposing their
// addresses.
func SystemInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, i := range ifs {
		fi := Iface{
			Name: i.Name,
			Up:   i.Flags&net.FlagUp != 0,
			Loop: i.Flags&net.FlagLoopback != 0,
			VPN:  IsVPNName(i.Name) || i.Flags&net.FlagPointToPoint != 0 && !strings.HasPrefix(i.Name, "utun"),
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() && !ipn.IP.IsLinkLocalUnicast() {
				fi.HasAddr = true
				break
			}
		}
		out = append(out, fi)
	}
	return out, nil
}

var vpnMarkers = []string{
	"tun", "tap", "wg", "ppp", "ipsec", "utun", "tailscale", "zt", "nordlynx",
	"wireguard", "openvpn", "vpn", "proton", "anyconnect", "wintun", "outline",
}

// IsVPNName reports whether an interface name looks like a VPN tunnel.
// Names are matched by prefix, except for Windows-style descriptive names,
// which are matched anywhere.
func IsVPNName(name string) bool {
	n := strings.ToLower(name)
	for _, m := range []string{"teredo", "isatap", "6to4"} {
		if strings.Contains(n, m) {
			return false // IPv6 transition adapters, not VPNs
		}
	}
	for _, m := range vpnMarkers {
		if strings.HasPrefix(n, m) {
			return true
		}
	}
	for _, m := range []string{"wireguard", "openvpn", "vpn", "tap-windows", "wintun", "anyconnect", "tunnel"} {
		if strings.Contains(n, m) {
			return true
		}
	}
	return false
}

// HasDefaultRoute reports whether the OS has a route to the Internet. It
// "connects" a UDP socket, which selects a route without sending anything.
func HasDefaultRoute() bool {
	for _, target := range []string{"192.0.2.1:9", "[2001:db8::1]:9"} {
		c, err := net.Dial("udp", target)
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

var proxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}

// ProxyEnv returns the names (never the values, which may hold
// credentials) of proxy environment variables that are set.
func ProxyEnv(getenv func(string) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range proxyVars {
		if getenv(v) != "" {
			up := strings.ToUpper(v)
			if !seen[up] {
				seen[up] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// DetectSystemProxy asks the OS whether a proxy is configured. It returns a
// short description such as "manual" or "HTTPS", or "" when none is set or
// the setting cannot be read.
func DetectSystemProxy(ctx context.Context) string {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.CommandContext(c, "scutil", "--proxy").Output()
		if err != nil {
			return ""
		}
		return parseScutil(string(out))
	case "windows":
		out, err := exec.CommandContext(c, "reg", "query",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`).Output()
		if err != nil {
			return ""
		}
		return parseWindowsReg(string(out))
	case "linux":
		out, err := exec.CommandContext(c, "gsettings", "get", "org.gnome.system.proxy", "mode").Output()
		if err != nil {
			return ""
		}
		return parseGSettings(string(out))
	}
	return ""
}

func parseScutil(s string) string {
	var kinds []string
	for _, k := range []string{"HTTP", "HTTPS", "SOCKS", "ProxyAutoConfig"} {
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && f[0] == k+"Enable" && f[2] == "1" {
				kinds = append(kinds, k)
			}
		}
	}
	return strings.Join(kinds, "+")
}

func parseWindowsReg(s string) string {
	var kinds []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "ProxyEnable" && f[2] == "0x1" {
			kinds = append(kinds, "manual")
		}
		if len(f) >= 3 && f[0] == "AutoConfigURL" {
			kinds = append(kinds, "PAC")
		}
	}
	return strings.Join(kinds, "+")
}

func parseGSettings(s string) string {
	mode := strings.Trim(strings.TrimSpace(s), "'")
	if mode == "manual" || mode == "auto" {
		return mode
	}
	return ""
}

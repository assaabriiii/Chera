package localnet

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/testutil"
)

func TestIsVPNName(t *testing.T) {
	for name, want := range map[string]bool{
		"tun0": true, "wg0": true, "utun3": true, "tailscale0": true, "ppp0": true,
		"WireGuard Tunnel": true, "OpenVPN TAP-Windows6": true, "Ethernet 2 (VPN)": true,
		"eth0": false, "en0": false, "wlan0": false, "Wi-Fi": false, "lo": false, "docker0": false,
		"Teredo Tunneling Pseudo-Interface": false,
	} {
		if got := IsVPNName(name); got != want {
			t.Errorf("IsVPNName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestProxyEnvNamesOnly(t *testing.T) {
	env := map[string]string{"HTTPS_PROXY": "http://user:secret@proxy:3128", "no_proxy": "localhost", "all_proxy": "socks5://x:1"}
	got := ProxyEnv(func(k string) string { return env[k] })
	if strings.Join(got, ",") != "HTTPS_PROXY,all_proxy" {
		t.Fatalf("ProxyEnv = %v", got)
	}
	for _, g := range got {
		if strings.Contains(g, "secret") {
			t.Fatal("leaked credentials")
		}
	}
}

func TestDown(t *testing.T) {
	eth := Iface{Name: "eth0", Up: true, HasAddr: true}
	lo := Iface{Name: "lo", Up: true, Loop: true, HasAddr: true}
	tests := []struct {
		name   string
		r      Result
		down   bool
		reason string
	}{
		{"healthy", Result{Interfaces: []Iface{lo, eth}, DefaultRoute: true, Baseline: []Probe{{OK: false}, {OK: true}}}, false, ""},
		{"no interface", Result{Interfaces: []Iface{lo, {Name: "eth0"}}, DefaultRoute: false}, true, DownNoInterface},
		{"no route", Result{Interfaces: []Iface{eth}, DefaultRoute: false}, true, DownNoRoute},
		{"nothing reachable", Result{Interfaces: []Iface{eth}, DefaultRoute: true, Baseline: []Probe{{}, {}}}, true, DownUnreachable},
		{"no baseline configured", Result{Interfaces: []Iface{eth}, DefaultRoute: true}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			down, reason := tt.r.Down()
			if down != tt.down || reason != tt.reason {
				t.Fatalf("Down() = %v, %q", down, reason)
			}
		})
	}
}

func TestVPNNames(t *testing.T) {
	r := Result{Interfaces: []Iface{
		{Name: "utun0", Up: true, VPN: true},                // macOS system tunnel without address
		{Name: "wg0", Up: true, VPN: true, HasAddr: true},   // active VPN
		{Name: "tun1", Up: false, VPN: true, HasAddr: true}, // down
	}}
	if got := r.VPNNames(); len(got) != 1 || got[0] != "wg0" {
		t.Fatalf("VPNNames = %v", got)
	}
}

func TestCheckBaseline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := Config{
		Dialer:      netx.Direct(time.Second),
		Timeout:     500 * time.Millisecond,
		Baseline:    []string{testutil.ClosedAddr(t, "tcp"), ln.Addr().String()},
		Interfaces:  func() ([]Iface, error) { return []Iface{{Name: "eth0", Up: true, HasAddr: true}}, nil },
		Route:       func() bool { return true },
		Getenv:      func(string) string { return "" },
		SystemProxy: func(context.Context) string { return "manual" },
	}
	r := Check(context.Background(), cfg)
	if r.Baseline[0].OK || !r.Baseline[1].OK || !r.AnyBaseline() || r.SystemProxy != "manual" {
		t.Fatalf("result = %+v", r)
	}
	if down, _ := r.Down(); down {
		t.Fatal("should be up")
	}

	cfg.Baseline = []string{testutil.ClosedAddr(t, "tcp")}
	if down, reason := Check(context.Background(), cfg).Down(); !down || reason != DownUnreachable {
		t.Fatalf("expected unreachable, got %v %q", down, reason)
	}

	cfg.Route = func() bool { return false }
	r = Check(context.Background(), cfg)
	if len(r.Baseline) != 0 {
		t.Fatal("baseline should be skipped without a route")
	}
}

func TestParsers(t *testing.T) {
	scutil := "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 1\n  HTTPSProxy : 127.0.0.1\n  SOCKSEnable : 1\n}"
	if got := parseScutil(scutil); got != "HTTPS+SOCKS" {
		t.Errorf("scutil = %q", got)
	}
	reg := "    ProxyEnable    REG_DWORD    0x1\r\n    ProxyServer    REG_SZ    127.0.0.1:8080\r\n"
	if got := parseWindowsReg(reg); got != "manual" {
		t.Errorf("reg = %q", got)
	}
	if got := parseWindowsReg("    ProxyEnable    REG_DWORD    0x0\r\n"); got != "" {
		t.Errorf("reg disabled = %q", got)
	}
	if parseGSettings("'manual'\n") != "manual" || parseGSettings("'none'") != "" {
		t.Error("gsettings")
	}
}

func TestSystemInterfacesDoesNotFail(t *testing.T) {
	ifs, err := SystemInterfaces()
	if err != nil {
		t.Skip("interfaces unavailable:", err)
	}
	for _, i := range ifs {
		if i.Name == "" {
			t.Fatal("interface without name")
		}
	}
}

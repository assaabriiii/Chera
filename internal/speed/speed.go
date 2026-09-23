// Package speed measures TLS handshake time and download throughput to a
// target and to a baseline host, and flags severe degradation that looks
// like throttling.
package speed

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"
)

// DefaultBaselineURL serves a fixed number of bytes from a large anycast
// network, which makes it a reasonable yardstick for "normal" speed.
const DefaultBaselineURL = "https://speed.cloudflare.com/__down?bytes=262144"

// Thresholds for the throttling decision.
const (
	// MinBytes is the smallest download that gives a meaningful rate.
	MinBytes = 64 << 10
	// MaxBytes caps each download so the check stays light.
	MaxBytes = 1 << 20
	// SlowRate is the rate below which a target counts as degraded.
	SlowRate = 256 << 10 // bytes per second
	// RateRatio is how many times slower than the baseline a target must be.
	RateRatio = 8
	// SlowHandshake and HandshakeRatio flag handshakes that take far longer
	// than the baseline's.
	SlowHandshake  = 1500 * time.Millisecond
	HandshakeRatio = 5
)

// Measurement is one timed download.
type Measurement struct {
	URL       string
	Status    int
	Bytes     int64
	Duration  time.Duration
	Handshake time.Duration
	Err       error
}

// Rate returns bytes per second.
func (m Measurement) Rate() float64 {
	if m.Duration <= 0 {
		return 0
	}
	return float64(m.Bytes) / m.Duration.Seconds()
}

// Measure downloads up to MaxBytes from url with client. A download cut
// off by the timeout still counts, since the bytes received so far are
// exactly what a throttled connection looks like.
func Measure(ctx context.Context, client *http.Client, url string, timeout time.Duration) Measurement {
	m := Measurement{URL: url}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var hsStart time.Time
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { hsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !hsStart.IsZero() {
				m.Handshake = time.Since(hsStart)
			}
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(c, trace), http.MethodGet, url, nil)
	if err != nil {
		m.Err = err
		return m
	}
	req.Header.Set("User-Agent", "chera")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		m.Duration = time.Since(start)
		m.Err = err
		return m
	}
	defer resp.Body.Close()
	m.Status = resp.StatusCode
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBytes))
	m.Duration = time.Since(start)
	m.Bytes = n
	// A timeout after some bytes arrived is a valid (slow) measurement.
	partial := errors.Is(err, context.DeadlineExceeded) && n > 0
	if err != nil && !partial {
		m.Err = err
	}
	return m
}

// Result compares a target with the baseline.
type Result struct {
	Target    Measurement
	Baseline  Measurement
	Throttled bool
	// Kind is "throughput" or "handshake" when Throttled.
	Kind string
}

// Compare applies the throttling thresholds.
func Compare(target, baseline Measurement) Result {
	r := Result{Target: target, Baseline: baseline}
	if target.Err != nil || baseline.Err != nil || !success(baseline.Status) {
		return r
	}
	if success(target.Status) && target.Bytes >= MinBytes && baseline.Bytes >= MinBytes {
		tr, br := target.Rate(), baseline.Rate()
		if tr < SlowRate && tr*RateRatio <= br {
			r.Throttled, r.Kind = true, "throughput"
			return r
		}
	}
	if target.Handshake > SlowHandshake && baseline.Handshake > 0 &&
		target.Handshake > HandshakeRatio*baseline.Handshake {
		r.Throttled, r.Kind = true, "handshake"
	}
	return r
}

func success(status int) bool { return status >= 200 && status < 300 }

// FormatRate renders a rate such as "120 KB/s".
func FormatRate(bps float64) string {
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.0f KB/s", bps/(1<<10))
	}
	return fmt.Sprintf("%.0f B/s", bps)
}

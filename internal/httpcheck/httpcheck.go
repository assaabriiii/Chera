// Package httpcheck requests a lightweight URL from the verified address of
// a service and classifies the response: block page, provider geo-block,
// server error, or a normal answer.
package httpcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/assaabriiii/chera/internal/netx"
	"github.com/assaabriiii/chera/internal/signatures"
)

// Class is the category of an HTTP response.
type Class string

// Response classes.
const (
	OK          Class = "ok"
	BlockPage   Class = "block_page"
	GeoBlock    Class = "geo_block"
	Legal       Class = "legal" // HTTP 451
	ServerError Class = "server_error"
	Failed      Class = "failed" // no response
)

// UserAgent identifies chera to servers. Some registries reject requests
// without a descriptive User-Agent.
const UserAgent = "chera (+https://github.com/assaabriiii/chera)"

// maxBody bounds how much of a response is read for classification.
const maxBody = 64 << 10

// Result is the outcome of one request.
type Result struct {
	URL       string
	Status    int
	Location  string
	Server    string
	Class     Class
	Signature string
	Snippet   string
	Err       error
	ErrKind   netx.ErrKind
	Duration  time.Duration
}

// Options configure a request.
type Options struct {
	Dialer  netx.Dialer
	Timeout time.Duration
	RootCAs *x509.CertPool
	// Addr is the ip:port every connection goes to, so the request reaches
	// the verified address instead of whatever the local DNS returns.
	Addr string
	// Insecure skips certificate verification; used only to read what an
	// intercepting middlebox serves.
	Insecure   bool
	Signatures *signatures.Set
}

// Fetch performs a GET on rawURL without following redirects.
func Fetch(ctx context.Context, o Options, rawURL string) Result {
	res := Result{URL: rawURL}
	c, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, rawURL, nil)
	if err != nil {
		res.Class, res.Err, res.ErrKind = Failed, err, netx.KindOther
		return res
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")

	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if o.Addr != "" {
				addr = o.Addr
			}
			return o.Dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			RootCAs:            o.RootCAs,
			InsecureSkipVerify: o.Insecure,
			MinVersion:         tls.VersionTLS12,
		},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   o.Timeout,
		ResponseHeaderTimeout: o.Timeout,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.Duration = time.Since(start)
		res.Class, res.Err, res.ErrKind = Failed, err, classifyErr(err)
		return res
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	res.Duration = time.Since(start)
	res.Status = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	res.Server = resp.Header.Get("Server")
	res.Snippet = snippet(body)
	res.Class, res.Signature = Classify(o.Signatures, req.URL.Hostname(), res.Status, res.Location, string(body))
	if readErr != nil && res.Class == OK && len(body) == 0 {
		res.Class, res.Err, res.ErrKind = Failed, readErr, classifyErr(readErr)
	}
	return res
}

func classifyErr(err error) netx.ErrKind {
	var ue interface{ Timeout() bool }
	if errors.As(err, &ue) && ue.Timeout() {
		return netx.KindTimeout
	}
	return netx.Classify(err)
}

// Classify decides what a response means.
func Classify(sigs *signatures.Set, host string, status int, location, body string) (Class, string) {
	if sigs != nil {
		if name := sigs.MatchBlockPage(location, body); name != "" {
			return BlockPage, name
		}
		if name := sigs.MatchGeoBlock(host, status, body); name != "" {
			return GeoBlock, name
		}
	}
	switch {
	case status == http.StatusUnavailableForLegalReasons:
		return Legal, ""
	case status >= 500:
		return ServerError, ""
	}
	return OK, ""
}

// snippet returns a short single-line preview of a body for evidence.
func snippet(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, string(b))
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "..."
	}
	return s
}

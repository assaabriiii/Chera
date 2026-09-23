// Package outage asks a service's official status page whether it is
// having an incident, so that a clean network path with a failing service
// can be reported as an upstream problem instead of blocking.
package outage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Result is what the status page said.
type Result struct {
	URL         string
	Indicator   string // none, minor, major, critical, maintenance
	Description string
	Err         error
}

// Confirmed reports whether the status page acknowledges a problem.
func (r Result) Confirmed() bool {
	switch r.Indicator {
	case "minor", "major", "critical":
		return true
	}
	return false
}

// Severe reports a major or critical incident.
func (r Result) Severe() bool {
	return r.Indicator == "major" || r.Indicator == "critical"
}

// statuspage is the shape of Atlassian Statuspage's /api/v2/status.json,
// which most developer services use.
type statuspage struct {
	Status struct {
		Indicator   string `json:"indicator"`
		Description string `json:"description"`
	} `json:"status"`
}

// Check fetches and parses a status.json URL.
func Check(ctx context.Context, client *http.Client, url string, timeout time.Duration) Result {
	res := Result{URL: url}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err
		return res
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		res.Err = err
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.Err = fmt.Errorf("status page answered HTTP %d", resp.StatusCode)
		return res
	}
	var sp statuspage
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&sp); err != nil {
		res.Err = fmt.Errorf("status page: %w", err)
		return res
	}
	if sp.Status.Indicator == "" {
		res.Err = fmt.Errorf("status page: no status indicator")
		return res
	}
	res.Indicator = sp.Status.Indicator
	res.Description = sp.Status.Description
	return res
}

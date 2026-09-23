// Package model holds the types shared by the diagnosis layers, the verdict
// engine and the report renderers.
package model

import "time"

// Verdict is the primary diagnosis for one target.
type Verdict string

// All verdicts Chera can produce.
const (
	OK               Verdict = "OK"
	LocalNetworkDown Verdict = "LOCAL_NETWORK_DOWN"
	DNSPoisoned      Verdict = "DNS_POISONED"
	DNSIntercepted   Verdict = "DNS_INTERCEPTED"
	IPBlocked        Verdict = "IP_BLOCKED"
	ConnectionReset  Verdict = "CONNECTION_RESET"
	SNIFiltered      Verdict = "SNI_FILTERED"
	TLSIntercepted   Verdict = "TLS_INTERCEPTED"
	BlockPage        Verdict = "BLOCK_PAGE"
	ProviderGeoBlock Verdict = "PROVIDER_GEO_BLOCK"
	Throttled        Verdict = "THROTTLED"
	UpstreamOutage   Verdict = "UPSTREAM_OUTAGE"
	Inconclusive     Verdict = "INCONCLUSIVE"
)

// AllVerdicts lists every verdict in a stable order, used for summaries.
var AllVerdicts = []Verdict{
	OK, LocalNetworkDown, DNSPoisoned, DNSIntercepted, IPBlocked,
	ConnectionReset, SNIFiltered, TLSIntercepted, BlockPage,
	ProviderGeoBlock, Throttled, UpstreamOutage, Inconclusive,
}

// Confidence expresses how sure the verdict engine is.
type Confidence string

// Confidence levels.
const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Target is one host to diagnose.
type Target struct {
	// Host is the DNS name, e.g. "github.com".
	Host string `yaml:"host" json:"host"`
	// URL is a lightweight HTTPS URL used by the HTTP layer. Defaults to
	// https://<host>/.
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
	// StatusPage is an optional Statuspage-compatible status.json URL used
	// by the outage check.
	StatusPage string `yaml:"status_page,omitempty" json:"status_page,omitempty"`
	// SpeedURL is an optional URL used by the throttling check. Defaults to
	// URL.
	SpeedURL string `yaml:"speed_url,omitempty" json:"speed_url,omitempty"`
	// Kind groups targets by ecosystem ("pypi", "npm", "docker", ...) so
	// suggestions can mention the right generic remedy.
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty"`
}

// CheckURL returns the URL the HTTP layer should request.
func (t Target) CheckURL() string {
	if t.URL != "" {
		return t.URL
	}
	return "https://" + t.Host + "/"
}

// Status is the outcome of a single check inside a layer.
type Status string

// Check statuses.
const (
	Pass Status = "pass"
	Fail Status = "fail"
	Warn Status = "warn"
	Info Status = "info"
	Skip Status = "skip"
)

// Evidence is one observation that supports a verdict.
type Evidence struct {
	Layer  string `json:"layer"`
	Check  string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

// Reason is a machine-readable explanation of a verdict. Key selects a
// translated message; Args fill its placeholders.
type Reason struct {
	Key  string            `json:"key"`
	Args map[string]string `json:"args,omitempty"`
}

// TargetReport is the full result for one target.
type TargetReport struct {
	Target     Target     `json:"target"`
	Verdict    Verdict    `json:"verdict"`
	Confidence Confidence `json:"confidence"`
	Reason     Reason     `json:"reason"`
	// Also lists secondary problems found on the way, e.g. DNS poisoning
	// on top of SNI filtering.
	Also     []Verdict     `json:"also,omitempty"`
	Evidence []Evidence    `json:"evidence"`
	Duration time.Duration `json:"-"`
}

// LocalSummary is the privacy-safe view of the local network layer that is
// included in reports. It never contains local IP addresses.
type LocalSummary struct {
	Up            bool     `json:"up"`
	DefaultRoute  bool     `json:"default_route"`
	Interfaces    []string `json:"interfaces"`
	VPNInterfaces []string `json:"vpn_interfaces,omitempty"`
	ProxyEnv      []string `json:"proxy_env,omitempty"`
	SystemProxy   string   `json:"system_proxy,omitempty"`
	Reachable     []string `json:"reachable_baseline"`
	Unreachable   []string `json:"unreachable_baseline,omitempty"`
	DNSIntercept  bool     `json:"dns_interception"`
	ProxyFlag     bool     `json:"proxy_flag"`
}

// Report is everything a run produced.
type Report struct {
	Version  string         `json:"version"`
	Started  time.Time      `json:"started"`
	Duration time.Duration  `json:"-"`
	OS       string         `json:"os"`
	Arch     string         `json:"arch"`
	Local    LocalSummary   `json:"local"`
	Targets  []TargetReport `json:"targets"`
}

// Package fingerprint implements banner-based protocol / product / version
// identification.
//
// The identification rules live entirely in a data file (YAML or JSON) so that
// the detection knowledge can be changed without touching or recompiling the
// program. See rules/rules.yaml for the rule schema.
package fingerprint

// Input is one raw scan record: the banner text a scanner captured for an
// (ip, port) pair.
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is the identification outcome for a single Input.
//
// Protocol is "unknown" (and Confidence 0) when nothing matched; identification
// failures are never an error, they are a result.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`

	// RuleID is only populated when the caller asks for an explanation
	// (?explain=1 on the HTTP API) so that the default payload stays exactly
	// the documented 7 fields.
	RuleID string `json:"rule_id,omitempty"`
}

// Unknown is the protocol value used when no rule matched.
const Unknown = "unknown"

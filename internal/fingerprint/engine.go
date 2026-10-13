package fingerprint

import (
	"math"
	"sort"
)

// Engine matches inputs against an ordered rule set. It is safe for concurrent
// use: all state is read-only after construction.
type Engine struct {
	rules  []*Rule
	source string
}

// NewEngine sorts the rules by descending priority (stable, so rules declared
// earlier win at equal priority) and returns a ready-to-use engine.
func NewEngine(rs *RuleSet) *Engine {
	rules := make([]*Rule, len(rs.Rules))
	copy(rules, rs.Rules)
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].order < rules[j].order
	})
	return &Engine{rules: rules, source: rs.Source}
}

// Rules returns the rule set in evaluation order.
func (e *Engine) Rules() []*Rule { return e.rules }

// Source reports where the rule set was loaded from.
func (e *Engine) Source() string { return e.source }

// Fingerprint identifies a single input. It never fails: unmatched inputs yield
// Protocol "unknown".
func (e *Engine) Fingerprint(in Input) Result {
	res := Result{
		IP:       in.IP,
		Port:     in.Port,
		Protocol: Unknown,
	}
	for _, r := range e.rules {
		if !r.matchesPort(in.Port) {
			continue
		}
		caps, ok := r.matchBanner(in.Banner)
		if !ok {
			continue
		}
		res.Protocol = r.Protocol
		res.Product = expand(r.Product, caps)
		res.Version = expand(r.Version, caps)
		res.OSHint = r.osHint(in.Banner, caps)
		res.Confidence = round2(r.Confidence)
		res.RuleID = r.ID
		return res
	}
	return res
}

// FingerprintAll identifies a batch, preserving input order.
func (e *Engine) FingerprintAll(in []Input) []Result {
	out := make([]Result, len(in))
	for i := range in {
		out[i] = e.Fingerprint(in[i])
	}
	return out
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

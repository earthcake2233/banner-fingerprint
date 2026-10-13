package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleSet is the on-disk rule document.
type RuleSet struct {
	Version int     `yaml:"version" json:"version"`
	Rules   []*Rule `yaml:"rules" json:"rules"`

	// Source records where the rules were loaded from (for /health reporting).
	Source string `yaml:"-" json:"-"`
}

// Rule describes how to recognise one protocol/product family.
//
// Matching is deliberately declarative:
//
//	ports       - optional port allow-list (empty = any port)
//	banner_any  - at least one regex must match the banner
//	banner_all  - every regex must match the banner
//	banner_none - no regex may match the banner (veto)
//
// Product / Version / os_hint names support {name} templates that are expanded
// with the named capture groups of the matching regexes.
type Rule struct {
	ID          string  `yaml:"id" json:"id"`
	Description string  `yaml:"description" json:"description"`
	Priority    int     `yaml:"priority" json:"priority"`
	Protocol    string  `yaml:"protocol" json:"protocol"`
	Product     string  `yaml:"product" json:"product"`
	Version     string  `yaml:"version" json:"version"`
	Confidence  float64 `yaml:"confidence" json:"confidence"`

	Ports      []int    `yaml:"ports" json:"ports"`
	BannerAny  []string `yaml:"banner_any" json:"banner_any"`
	BannerAll  []string `yaml:"banner_all" json:"banner_all"`
	BannerNone []string `yaml:"banner_none" json:"banner_none"`
	OSHint     []OSRule `yaml:"os_hint" json:"os_hint"`

	any   []*regexp.Regexp
	all   []*regexp.Regexp
	none  []*regexp.Regexp
	osRE  []*regexp.Regexp
	order int
}

// OSRule maps a banner fragment to an operating-system hint.
type OSRule struct {
	Name  string `yaml:"name" json:"name"`
	Regex string `yaml:"regex" json:"regex"`
}

// LoadRuleSet parses a rule document. YAML and JSON are both accepted; the
// format is detected from the content, not from the file extension.
func LoadRuleSet(path string, data []byte) (*RuleSet, error) {
	var rs RuleSet
	trimmed := strings.TrimSpace(string(data))
	switch {
	case strings.HasPrefix(trimmed, "{"):
		if err := json.Unmarshal(data, &rs); err != nil {
			return nil, fmt.Errorf("parse json rules: %w", err)
		}
	default:
		if err := yaml.Unmarshal(data, &rs); err != nil {
			return nil, fmt.Errorf("parse yaml rules: %w", err)
		}
	}
	rs.Source = path
	if err := rs.compile(); err != nil {
		return nil, err
	}
	return &rs, nil
}

// LoadPath loads rules from a file, or merges every *.yaml/*.yml/*.json file of
// a directory (sorted by file name) into a single rule set.
func LoadPath(path string) (*RuleSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return LoadRuleSet(path, data)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".yaml", ".yml", ".json":
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no rule files (*.yaml, *.yml, *.json) in %s", path)
	}

	merged := &RuleSet{Source: path}
	for _, name := range names {
		full := filepath.Join(path, name)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		part, err := LoadRuleSet(full, data)
		if err != nil {
			return nil, err
		}
		if part.Version > merged.Version {
			merged.Version = part.Version
		}
		merged.Rules = append(merged.Rules, part.Rules...)
	}
	merged.Source = path
	if err := merged.compile(); err != nil {
		return nil, err
	}
	return merged, nil
}

func (rs *RuleSet) compile() error {
	if len(rs.Rules) == 0 {
		return fmt.Errorf("rule set %s contains no rules", rs.Source)
	}
	seen := make(map[string]bool, len(rs.Rules))
	for i, r := range rs.Rules {
		if r == nil {
			return fmt.Errorf("rule #%d is empty", i)
		}
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("rule #%d has no id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Protocol) == "" {
			return fmt.Errorf("rule %q has no protocol", r.ID)
		}
		if len(r.BannerAny) == 0 && len(r.BannerAll) == 0 {
			return fmt.Errorf("rule %q has no banner_any/banner_all matcher", r.ID)
		}
		if r.Confidence < 0 || r.Confidence > 1 {
			return fmt.Errorf("rule %q confidence %v out of range [0,1]", r.ID, r.Confidence)
		}
		r.order = i
		var err error
		if r.any, err = compileAll(r.ID, "banner_any", r.BannerAny); err != nil {
			return err
		}
		if r.all, err = compileAll(r.ID, "banner_all", r.BannerAll); err != nil {
			return err
		}
		if r.none, err = compileAll(r.ID, "banner_none", r.BannerNone); err != nil {
			return err
		}
		r.osRE = r.osRE[:0]
		for _, o := range r.OSHint {
			re, err := regexp.Compile(o.Regex)
			if err != nil {
				return fmt.Errorf("rule %q: invalid os_hint regex %q: %w", r.ID, o.Regex, err)
			}
			r.osRE = append(r.osRE, re)
		}
	}
	return nil
}

func compileAll(id, field string, patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("rule %q: invalid %s regex %q: %w", id, field, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// matchesPort reports whether the rule applies to the given port.
func (r *Rule) matchesPort(port int) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// matchBanner evaluates the banner constraints and returns the merged named
// capture groups of the matching patterns (nil, false when the rule does not
// apply to this banner).
func (r *Rule) matchBanner(banner string) (map[string]string, bool) {
	caps := map[string]string{}

	if len(r.any) > 0 {
		if !collectFirstMatch(r.any, banner, caps) {
			return nil, false
		}
	}
	for _, re := range r.all {
		m := re.FindStringSubmatch(banner)
		if m == nil {
			return nil, false
		}
		collect(re, m, caps)
	}
	for _, re := range r.none {
		if re.MatchString(banner) {
			return nil, false
		}
	}
	return caps, true
}

func collectFirstMatch(res []*regexp.Regexp, banner string, caps map[string]string) bool {
	for _, re := range res {
		m := re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		collect(re, m, caps)
		return true
	}
	return false
}

// collect merges named capture groups into caps. The first value seen for a
// name wins so that earlier (usually more specific) patterns take precedence.
func collect(re *regexp.Regexp, m []string, caps map[string]string) {
	for i, name := range re.SubexpNames() {
		if i == 0 || name == "" || i >= len(m) {
			continue
		}
		if _, exists := caps[name]; exists {
			continue
		}
		caps[name] = m[i]
	}
}

// osHint returns the first matching operating-system hint, expanded against the
// captures of the banner matchers merged with the captures of the hint itself.
func (r *Rule) osHint(banner string, caps map[string]string) string {
	for i, re := range r.osRE {
		m := re.FindStringSubmatch(banner)
		if m == nil {
			continue
		}
		merged := make(map[string]string, len(caps)+len(r.OSHint[i].Name))
		for k, v := range caps {
			merged[k] = v
		}
		collect(re, m, merged)
		return strings.TrimSpace(expand(r.OSHint[i].Name, merged))
	}
	return ""
}

// expand substitutes {name} placeholders; unknown placeholders become "".
func expand(tmpl string, caps map[string]string) string {
	if tmpl == "" || !strings.Contains(tmpl, "{") {
		return tmpl
	}
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '{' {
			b.WriteByte(tmpl[i])
			i++
			continue
		}
		end := strings.IndexByte(tmpl[i:], '}')
		if end < 0 {
			b.WriteString(tmpl[i:])
			break
		}
		name := tmpl[i+1 : i+end]
		b.WriteString(caps[name])
		i += end + 1
	}
	return b.String()
}

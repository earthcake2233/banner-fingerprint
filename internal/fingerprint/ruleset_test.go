package fingerprint

import (
	"os"
	"testing"

	"github.com/earthcake2233/banner-fingerprint/internal/fingerprint/builtin"
)

// TestEmbeddedRulesMatchShippedRules guards against the embedded fallback and
// the file mounted into the container drifting apart.
func TestEmbeddedRulesMatchShippedRules(t *testing.T) {
	shipped, err := os.ReadFile("../../rules/rules.yaml")
	if err != nil {
		t.Fatalf("read rules/rules.yaml: %v", err)
	}
	if string(shipped) != string(builtin.RulesYAML) {
		t.Fatal("rules/rules.yaml and internal/fingerprint/builtin/rules.yaml differ; run `make sync-rules`")
	}
}

func TestLoadRulesFromFileAndDirectory(t *testing.T) {
	rs, err := LoadPath("../../rules/rules.yaml")
	if err != nil {
		t.Fatalf("load file: %v", err)
	}
	if len(rs.Rules) == 0 {
		t.Fatal("no rules loaded from file")
	}

	dir, err := LoadPath("../../rules")
	if err != nil {
		t.Fatalf("load directory: %v", err)
	}
	if len(dir.Rules) != len(rs.Rules) {
		t.Fatalf("directory load returned %d rules, file load returned %d", len(dir.Rules), len(rs.Rules))
	}
}

func TestBrokenRulesAreRejected(t *testing.T) {
	broken := []string{
		"version: 1\nrules: []\n",
		"version: 1\nrules:\n  - id: x\n    priority: 1\n    protocol: X\n    confidence: 5\n    banner_any: ['x']\n",
		"version: 1\nrules:\n  - id: x\n    priority: 1\n    protocol: X\n    confidence: 0.5\n    banner_any: ['(']\n",
	}
	for i, doc := range broken {
		if _, err := LoadRuleSet("test", []byte(doc)); err == nil {
			t.Errorf("case %d: expected an error for an invalid rule set", i)
		}
	}
}

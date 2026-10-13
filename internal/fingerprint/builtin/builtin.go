// Package builtin carries a copy of rules/rules.yaml so the binary always has a
// usable rule set even when no external rules file is mounted.
//
// Keeping it in its own package (instead of importing the parent package) avoids
// an import cycle and keeps the embedded data obviously separate from code.
package builtin

import _ "embed"

// Name identifies the embedded rule source in /health output.
const Name = "builtin/rules.yaml"

// RulesYAML is the embedded fallback rule set. A file passed via -rules /
// FP_RULES always takes precedence over it.
//
//go:embed rules.yaml
var RulesYAML []byte

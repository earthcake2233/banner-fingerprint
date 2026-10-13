// Package jsonutil decodes scanner output tolerantly.
//
// Real-world scan dumps are frequently *almost* JSON: binary banner bytes are
// written as C-style \xNN escapes (which strict JSON rejects), and some export
// pipelines double every quote. Decoding therefore retries with repairs before
// giving up, so a slightly malformed batch degrades into "unmatched" results
// instead of a failed request.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	reQuoteRuns = regexp.MustCompile(`"{2,}`)
)

// envelopeKeys are the wrapper keys accepted around an array of records.
var envelopeKeys = []string{"items", "data", "records", "results", "hosts", "inputs", "banners", "rows"}

// DecodeRecords parses a batch of records from JSON. Accepted shapes:
//
//	[ {...}, {...} ]                          array of objects
//	{"items": [ ... ]}                        envelope object
//	{ ... }                                   a single record
//	{...}\n{...}\n                            NDJSON / JSON Lines
func DecodeRecords[T any](raw []byte) ([]T, error) {
	raw = stripBOM(raw)
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	strict, errStrict := decodeOnce[T](raw)
	if errStrict == nil {
		return strict, nil
	}
	if repaired, err := decodeOnce[T](RepairHexEscapes(raw)); err == nil {
		return repaired, nil
	}
	if repaired, err := decodeOnce[T](RepairDoubledQuotes(RepairHexEscapes(raw))); err == nil {
		return repaired, nil
	}
	return nil, errStrict
}

// RepairHexEscapes rewrites C-style \xNN escapes (invalid in JSON) into the
// equivalent \u00NN escape, which strict JSON accepts.
func RepairHexEscapes(raw []byte) []byte {
	// Scanned by hand rather than with a regexp: consecutive escapes such as
	// "\x00\x00" have no independent "previous character" for a look-behind,
	// which RE2 does not support anyway.
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			switch {
			case raw[i+1] == '\\':
				// Keep escaped backslashes untouched.
				out = append(out, raw[i], raw[i+1])
				i++
				continue
			case raw[i+1] == 'x' && i+3 < len(raw) && isHex(raw[i+2]) && isHex(raw[i+3]):
				out = append(out, '\\', 'u', '0', '0', raw[i+2], raw[i+3])
				i += 3
				continue
			}
		}
		out = append(out, raw[i])
	}
	return out
}

// RepairDoubledQuotes collapses runs of two or more quotes into a single quote,
// repairing exports where every quote was escaped twice ("\"\"ip\"\"" -> "ip").
// It is only applied after the stricter attempts failed.
func RepairDoubledQuotes(raw []byte) []byte {
	return reQuoteRuns.ReplaceAll(raw, []byte(`"`))
}

func decodeOnce[T any](data []byte) ([]T, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	switch trimmed[0] {
	case '[':
		var out []T
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, err
		}
		return out, nil
	case '{':
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &envelope); err == nil {
			for _, key := range envelopeKeys {
				rawArr, ok := envelope[key]
				if !ok {
					continue
				}
				inner := bytes.TrimSpace(rawArr)
				if len(inner) == 0 || inner[0] != '[' {
					continue
				}
				var out []T
				if err := json.Unmarshal(inner, &out); err != nil {
					return nil, err
				}
				return out, nil
			}
		}
		var single T
		if err := json.Unmarshal(trimmed, &single); err == nil {
			return []T{single}, nil
		}
		return decodeNDJSON[T](data)
	default:
		return decodeNDJSON[T](data)
	}
}

func decodeNDJSON[T any](data []byte) ([]T, error) {
	var out []T
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var rec T
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", len(out)+1, err)
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no records found")
	}
	return out, nil
}

func stripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

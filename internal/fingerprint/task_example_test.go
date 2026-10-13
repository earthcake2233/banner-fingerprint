package fingerprint

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/earthcake2233/banner-fingerprint/internal/jsonutil"
)

// TestTaskExampleMatchesExpectedOutput is the acceptance test for the task's own
// reference pair: it feeds samples/task-example-input.json through the engine and
// compares every documented field against samples/task-example-expected.json.
func TestTaskExampleMatchesExpectedOutput(t *testing.T) {
	inputs := mustDecode[Input](t, "../../samples/task-example-input.json")
	expected := mustDecode[Result](t, "../../samples/task-example-expected.json")

	if len(inputs) != 20 {
		t.Fatalf("reference input has %d records, want 20", len(inputs))
	}
	if len(expected) == 0 {
		t.Fatal("reference expectation file is empty")
	}

	engine := testEngine(t)
	got := engine.FingerprintAll(inputs)

	t.Logf("%-10s %-6s %-8s %-14s %-8s %-7s %s", "ip", "port", "protocol", "product", "version", "os_hint", "conf")
	for i, want := range expected {
		have := got[i]
		t.Logf("%-10s %-6d %-8s %-14s %-8s %-7s %.2f",
			have.IP, have.Port, have.Protocol, have.Product, have.Version, have.OSHint, have.Confidence)

		if have.IP != want.IP || have.Port != want.Port {
			t.Errorf("record %d identified out of order: got %s:%d, want %s:%d", i, have.IP, have.Port, want.IP, want.Port)
		}
		if have.Protocol != want.Protocol {
			t.Errorf("%s:%d protocol = %q, want %q", want.IP, want.Port, have.Protocol, want.Protocol)
		}
		if have.Product != want.Product {
			t.Errorf("%s:%d product = %q, want %q", want.IP, want.Port, have.Product, want.Product)
		}
		if have.Version != want.Version {
			t.Errorf("%s:%d version = %q, want %q", want.IP, want.Port, have.Version, want.Version)
		}
		if have.OSHint != want.OSHint {
			t.Errorf("%s:%d os_hint = %q, want %q", want.IP, want.Port, have.OSHint, want.OSHint)
		}
		if have.Confidence != want.Confidence {
			t.Errorf("%s:%d confidence = %v, want %v", want.IP, want.Port, have.Confidence, want.Confidence)
		}
	}
}

// TestResultJSONContract pins the wire format: exactly the seven documented
// fields (rule_id only appears when ?explain=1 asks for it).
func TestResultJSONContract(t *testing.T) {
	engine := testEngine(t)
	blob, err := json.Marshal(engine.Fingerprint(Input{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantKeys := []string{"confidence", "ip", "os_hint", "port", "product", "protocol", "version"}
	gotKeys := make([]string, 0, len(decoded))
	for k := range decoded {
		gotKeys = append(gotKeys, k)
	}
	sortStrings(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("result JSON keys = %v, want %v", gotKeys, wantKeys)
	}
}

// TestEveryReferenceRecordIsIdentified sums up the reference data: 20 records
// in, 19 identified, exactly one unknown (the "QUIT\r\n" line on port 12345).
func TestEveryReferenceRecordIsIdentified(t *testing.T) {
	inputs := mustDecode[Input](t, "../../samples/task-example-input.json")
	results := testEngine(t).FingerprintAll(inputs)

	counts := map[string]int{}
	for _, r := range results {
		counts[r.Protocol]++
	}
	t.Logf("protocol histogram: %v", counts)

	if counts[Unknown] != 1 {
		t.Fatalf("unknown = %d, want exactly 1; histogram = %v", counts[Unknown], counts)
	}
	for _, family := range []string{"SSH", "HTTP", "MySQL", "Redis", "FTP"} {
		if counts[family] == 0 {
			t.Errorf("required family %s was never detected", family)
		}
	}
}

func mustDecode[T any](t *testing.T, path string) []T {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out, err := jsonutil.DecodeRecords[T](raw)
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

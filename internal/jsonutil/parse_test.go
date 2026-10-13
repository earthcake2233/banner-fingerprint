package jsonutil

import (
	"strings"
	"testing"
)

type record struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

func TestDecodeAcceptedShapes(t *testing.T) {
	cases := map[string]string{
		"array":              `[{"ip":"1.1.1.1","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}]`,
		"envelope-items":     `{"items":[{"ip":"1.1.1.1","port":22,"banner":"x"}]}`,
		"envelope-results":   `{"results":[{"ip":"1.1.1.1","port":22,"banner":"x"}]}`,
		"single-object":      `{"ip":"1.1.1.1","port":22,"banner":"x"}`,
		"ndjson":             "{\"ip\":\"1.1.1.1\",\"port\":22,\"banner\":\"x\"}\n{\"ip\":\"1.1.1.2\",\"port\":23,\"banner\":\"y\"}\n",
		"bom-and-whitespace": "\ufeff\n [ {\"ip\":\"1.1.1.1\",\"port\":22,\"banner\":\"x\"} ] \n",
	}
	for name, doc := range cases {
		got, err := DecodeRecords[record]([]byte(doc))
		if err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
			continue
		}
		if len(got) == 0 {
			t.Errorf("%s: no records decoded", name)
		}
	}
}

// Scanner exports frequently contain C-style \xNN escapes, which are invalid
// JSON; the decoder repairs them instead of failing the whole batch.
func TestDecodeRepairsHexEscapes(t *testing.T) {
	doc := `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`
	got, err := DecodeRecords[record]([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("records = %d", len(got))
	}
	if !strings.Contains(got[0].Banner, "8.0.32") {
		t.Fatalf("banner = %q", got[0].Banner)
	}
	if !strings.ContainsRune(got[0].Banner, 0) {
		t.Fatalf("expected real NUL bytes after repair, banner = %q", got[0].Banner)
	}
}

func TestDecodeRepairsDoubledQuotes(t *testing.T) {
	doc := `[{""ip"":""1.2.3.9"",""port"":21,""banner"":""220 ProFTPD 1.3.7 Server (ProFTPD)""}]`
	got, err := DecodeRecords[record]([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].IP != "1.2.3.9" || got[0].Port != 21 {
		t.Fatalf("decoded = %+v", got)
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := DecodeRecords[record]([]byte("")); err == nil {
		t.Error("empty payload should error")
	}
	if _, err := DecodeRecords[record]([]byte("not json at all")); err == nil {
		t.Error("garbage should error")
	}
}

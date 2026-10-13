package fingerprint

import (
	"os"
	"testing"

	"github.com/earthcake2233/banner-fingerprint/internal/fingerprint/builtin"
	"github.com/earthcake2233/banner-fingerprint/internal/jsonutil"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	rs, err := LoadRuleSet("test:embedded", builtin.RulesYAML)
	if err != nil {
		t.Fatalf("load embedded rules: %v", err)
	}
	return NewEngine(rs)
}

// TestFingerprintSampleBatch pins the identification depth that the service is
// expected to reach on the reference sample data.
func TestFingerprintSampleBatch(t *testing.T) {
	engine := testEngine(t)

	cases := []struct {
		name             string
		in               Input
		protocol         string
		product, version string
		osHint           string
		confidence       float64
	}{
		{"openssh-ubuntu", Input{"1.2.3.4", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		{"nginx", Input{"1.2.3.5", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", "", 0.9},
		{"apache", Input{"1.2.3.6", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", "", 0.9},
		{"mysql-8", Input{"1.2.3.7", 3306, "J\x00\x00\x00\n8.0.32\x00"}, "MySQL", "MySQL", "8.0.32", "", 0.9},
		{"redis-error", Input{"1.2.3.8", 6379, "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", "", 0.7},
		{"proftpd", Input{"1.2.3.9", 21, "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", "", 0.9},
		{"jetty", Input{"1.2.3.10", 8080, "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", "", 0.85},
		{"openssh-debian", Input{"1.2.3.11", 22, "SSH-2.0-OpenSSH_9.3 Debian-1"}, "SSH", "OpenSSH", "9.3", "Debian", 0.95},
		{"nginx-ubuntu", Input{"1.2.3.12", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, "HTTP", "nginx", "1.18.0", "Ubuntu", 0.9},
		{"apache-ubuntu", Input{"1.2.3.13", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"}, "HTTP", "Apache", "2.4.41", "Ubuntu", 0.9},
		{"mysql-5.7", Input{"1.2.3.14", 3306, "J\x00\x00\x00\n5.7.42\x00"}, "MySQL", "MySQL", "5.7.42", "", 0.9},
		{"redis-pong", Input{"1.2.3.15", 6379, "+PONG"}, "Redis", "Redis", "", "", 0.7},
		{"vsftpd", Input{"1.2.3.16", 21, "220 (vsFTPd 3.0.5)"}, "FTP", "vsFTPd", "3.0.5", "", 0.9},
		{"nginx-8443", Input{"1.2.3.17", 8443, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"}, "HTTP", "nginx", "1.25.3", "", 0.9},
		{"openssh-legacy", Input{"1.2.3.18", 22, "SSH-1.99-OpenSSH_4.3"}, "SSH", "OpenSSH", "4.3", "", 0.95},
		{"tls-record", Input{"1.2.3.19", 9999, "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, "TLS", "", "", "", 0.6},
		{"iis", Input{"1.2.3.20", 8888, "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, "HTTP", "Microsoft-IIS", "10.0", "", 0.9},
		{"redis-noauth", Input{"1.2.3.21", 6379, "-NOAUTH Authentication required."}, "Redis", "Redis", "", "", 0.7},
		{"pure-ftpd", Input{"1.2.3.22", 21, "220 Welcome to Pure-FTPd"}, "FTP", "Pure-FTPd", "", "", 0.85},
	}

	for _, tc := range cases {
		got := engine.Fingerprint(tc.in)
		if got.Protocol != tc.protocol {
			t.Errorf("%s: protocol = %q, want %q", tc.name, got.Protocol, tc.protocol)
		}
		if got.Product != tc.product {
			t.Errorf("%s: product = %q, want %q", tc.name, got.Product, tc.product)
		}
		if got.Version != tc.version {
			t.Errorf("%s: version = %q, want %q", tc.name, got.Version, tc.version)
		}
		if got.OSHint != tc.osHint {
			t.Errorf("%s: os_hint = %q, want %q", tc.name, got.OSHint, tc.osHint)
		}
		if got.Confidence != tc.confidence {
			t.Errorf("%s: confidence = %v, want %v", tc.name, got.Confidence, tc.confidence)
		}
		if got.IP != tc.in.IP || got.Port != tc.in.Port {
			t.Errorf("%s: identity fields not preserved: %+v", tc.name, got)
		}
	}
}

// TestUnknownBannersAreResultsNotErrors covers the "must not blow up" rule:
// anything unrecognised is a normal result carrying protocol "unknown".
func TestUnknownBannersAreResultsNotErrors(t *testing.T) {
	engine := testEngine(t)
	inputs := []Input{
		{"1.2.3.23", 12345, "QUIT\r\n"},
		{"1.2.3.24", 4444, ""},
		{"1.2.3.25", 1, "\x00\x01\x02\x03binary garbage\xff"},
		{"1.2.3.26", 0, "totally unrecognisable banner"},
	}
	for _, in := range inputs {
		got := engine.Fingerprint(in)
		if got.Protocol != Unknown {
			t.Errorf("%+v: protocol = %q, want %q", in, got.Protocol, Unknown)
		}
		if got.Confidence != 0 {
			t.Errorf("%+v: confidence = %v, want 0", in, got.Confidence)
		}
		if got.Product != "" || got.Version != "" || got.OSHint != "" {
			t.Errorf("%+v: expected empty product/version/os_hint, got %+v", in, got)
		}
	}
}

// TestSampleFileIsIdentified makes sure the shipped sample file still parses and
// identifies, so `docker compose run client -input /data/input.json` can never
// regress into a wall of unknowns.
func TestSampleFileIsIdentified(t *testing.T) {
	raw, err := os.ReadFile("../../samples/input.json")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	inputs, err := jsonutil.DecodeRecords[Input](raw)
	if err != nil {
		t.Fatalf("decode sample: %v", err)
	}
	if len(inputs) != 20 {
		t.Fatalf("sample has %d records, want 20", len(inputs))
	}
	engine := testEngine(t)
	results := engine.FingerprintAll(inputs)
	unknown := 0
	for _, r := range results {
		if r.Protocol == Unknown {
			unknown++
		}
	}
	if unknown != 1 { // only "QUIT\r\n" on 12345 is expected to stay unknown
		t.Errorf("unknown results = %d, want 1 (results: %+v)", unknown, results)
	}
}

// TestTemplatesAreForwardCompatible documents that {unknown} placeholders
// resolve to an empty string instead of leaking the raw template.
func TestExpandTemplates(t *testing.T) {
	got := expand("nginx/{version}-{missing}", map[string]string{"version": "1.24.0"})
	if got != "nginx/1.24.0-" {
		t.Fatalf("expand = %q", got)
	}
}

package httpapi_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/earthcake2233/banner-fingerprint/internal/fingerprint"
	"github.com/earthcake2233/banner-fingerprint/internal/httpapi"
)

// apiHandler builds the real handler (embedded rules, discarded logs). Requests
// are driven through httptest.NewRequest/ResponseRecorder so the unit tests do
// not need to bind a socket.
func apiHandler(t *testing.T) http.Handler {
	t.Helper()
	store, err := fingerprint.NewStore("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return httpapi.New(store, slog.New(slog.NewTextHandler(io.Discard, nil)), httpapi.Config{
		Version: "test",
	}).Handler()
}

func do(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestFingerprintEndpointReturnsArray(t *testing.T) {
	h := apiHandler(t)
	body := `[
	  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
	  {"ip":"1.2.3.6","port":443,"banner":"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
	  {"ip":"1.2.3.9","port":21,"banner":"220 ProFTPD 1.3.7 Server (ProFTPD)"},
	  {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
	]`

	rec := do(t, h, http.MethodPost, "/fingerprint", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var results []fingerprint.Result
	if err := json.NewDecoder(rec.Body).Decode(&results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("results = %d, want 5", len(results))
	}
	want := []struct{ protocol, product, version string }{
		{"SSH", "OpenSSH", "8.9p1"},
		{"HTTP", "nginx", "1.24.0"},
		{"HTTP", "Apache", "2.4.57"},
		{"FTP", "ProFTPD", "1.3.7"},
		{fingerprint.Unknown, "", ""},
	}
	for i, w := range want {
		got := results[i]
		if got.Protocol != w.protocol || got.Product != w.product || got.Version != w.version {
			t.Errorf("result %d = %+v, want %+v", i, got, w)
		}
	}
}

func TestFingerprintEndpointToleratesMessyPayload(t *testing.T) {
	h := apiHandler(t)
	// \x00 is not valid JSON - the server repairs it instead of returning 400.
	body := `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`
	rec := do(t, h, http.MethodPost, "/fingerprint", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var results []fingerprint.Result
	if err := json.NewDecoder(rec.Body).Decode(&results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(results) != 1 || results[0].Version != "8.0.32" || results[0].Protocol != "MySQL" {
		t.Fatalf("results = %+v", results)
	}
}

func TestFingerprintEndpointRejectsGarbage(t *testing.T) {
	rec := do(t, apiHandler(t), http.MethodPost, "/fingerprint", "this is not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestFingerprintEndpointMethodNotAllowed(t *testing.T) {
	rec := do(t, apiHandler(t), http.MethodGet, "/fingerprint", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHealthAndRulesEndpoints(t *testing.T) {
	h := apiHandler(t)

	rec := do(t, h, http.MethodGet, "/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
	var health struct {
		Status string `json:"status"`
		Rules  struct {
			Count int `json:"count"`
		} `json:"rules"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health.Status != "ok" || health.Rules.Count == 0 {
		t.Fatalf("health = %+v", health)
	}

	if rec := do(t, h, http.MethodGet, "/rules", ""); rec.Code != http.StatusOK {
		t.Fatalf("rules status = %d", rec.Code)
	}
}

func TestWrappedAndExplainResponse(t *testing.T) {
	h := apiHandler(t)
	body := `[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}]`

	rec := do(t, h, http.MethodPost, "/fingerprint?wrap=1&explain=1", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var payload struct {
		Count   int                  `json:"count"`
		Unknown int                  `json:"unknown"`
		Results []fingerprint.Result `json:"results"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Count != 1 || payload.Results[0].RuleID == "" {
		t.Fatalf("payload = %+v", payload)
	}
}

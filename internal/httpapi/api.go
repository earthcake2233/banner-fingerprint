// Package httpapi exposes the fingerprinting service over HTTP.
package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/earthcake2233/banner-fingerprint/internal/fingerprint"
	"github.com/earthcake2233/banner-fingerprint/internal/jsonutil"
)

// Config carries the tunables of the HTTP layer.
type Config struct {
	// MaxBodyBytes bounds a single request body (default 16 MiB).
	MaxBodyBytes int64
	// Version is reported by /health.
	Version string
}

// Server wires the rule store into HTTP handlers.
type Server struct {
	store   *fingerprint.Store
	log     *slog.Logger
	cfg     Config
	started time.Time
	seq     atomic.Uint64
}

// New builds the HTTP layer.
func New(store *fingerprint.Store, log *slog.Logger, cfg Config) *Server {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 16 << 20
	}
	return &Server{store: store, log: log, cfg: cfg, started: time.Now()}
}

// Handler returns the fully wired router (routes + middleware).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/fingerprint", s.handleFingerprint)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/rules", s.handleRules)
	mux.HandleFunc("/", s.handleIndex)
	return s.withMiddleware(mux)
}

// handleFingerprint implements POST /fingerprint: a batch of raw scan records
// in, one identification result per record out, in the same order.
//
// Response shape:
//
//	default        : bare JSON array (matches the documented contract)
//	?wrap=1        : {"count":N,"unknown":K,"results":[...]}
//	?explain=1     : adds the rule_id that produced each result
func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "use POST /fingerprint")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read request body: "+err.Error())
		return
	}
	if int64(len(body)) > s.cfg.MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload exceeds limit")
		return
	}

	// Decoding is deliberately forgiving: a malformed batch is a client error,
	// never a panic, and unrecognised banners are values, not failures.
	inputs, err := jsonutil.DecodeRecords[fingerprint.Input](body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid scan payload: "+err.Error())
		return
	}

	engine := s.store.Engine()

	q := r.URL.Query()
	explain := truthy(q.Get("explain"))
	wrapped := truthy(q.Get("wrap")) || strings.Contains(strings.ToLower(q.Get("format")), "wrap")

	var results []fingerprint.Result
	if explain {
		results = engine.FingerprintAllExplained(inputs)
	} else {
		results = engine.FingerprintAll(inputs)
	}

	unknown := 0
	for _, res := range results {
		if res.Protocol == fingerprint.Unknown {
			unknown++
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Fingerprint-Rules", engine.Source())
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if wrapped {
		_ = enc.Encode(map[string]any{
			"count":   len(results),
			"unknown": unknown,
			"results": results,
		})
		return
	}
	_ = enc.Encode(results)
}

// handleHealth implements GET /health.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	engine := s.store.Engine()
	status := "ok"
	code := http.StatusOK
	rules := engine.Rules()
	if len(rules) == 0 {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	payload := map[string]any{
		"status":   status,
		"version":  s.cfg.Version,
		"uptime_s": int64(time.Since(s.started).Seconds()),
		"rules": map[string]any{
			"source":    engine.Source(),
			"count":     len(rules),
			"loaded_at": s.store.LoadedAt().UTC().Format(time.RFC3339),
			"reloaded":  s.store.ReloadError() == "",
			"error":     s.store.ReloadError(),
		},
	}
	writeJSON(w, code, payload)
}

// handleRules exposes the loaded rule catalogue, which makes it obvious that
// detection knowledge is data, not code.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	engine := s.store.Engine()
	type ruleView struct {
		ID         string  `json:"id"`
		Protocol   string  `json:"protocol"`
		Product    string  `json:"product"`
		Priority   int     `json:"priority"`
		Confidence float64 `json:"confidence"`
		Ports      []int   `json:"ports,omitempty"`
	}
	out := make([]ruleView, 0, len(engine.Rules()))
	for _, r := range engine.Rules() {
		out = append(out, ruleView{r.ID, r.Protocol, r.Product, r.Priority, r.Confidence, r.Ports})
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": engine.Source(), "count": len(out), "rules": out})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, strings.Join([]string{
		"banner-fingerprint server",
		"",
		"  POST /fingerprint   batch identify raw banners (JSON array, envelope or NDJSON)",
		"  GET  /health        liveness/readiness probe (used by docker compose healthcheck)",
		"  GET  /rules         loaded rule catalogue (rules are data, not code)",
		"",
		"Example:",
		`  curl -sS -X POST localhost:8080/fingerprint -d '[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]'`,
		"",
	}, "\n"))
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := s.seq.Add(1)
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		rec.Header().Set("X-Request-Id", strconv.FormatUint(id, 10))
		rec.Header().Set("X-Content-Type-Options", "nosniff")

		defer func() {
			if rv := recover(); rv != nil {
				// A panic in one request must not take the service down.
				s.log.Error("panic while handling request",
					"request_id", id, "path", r.URL.Path, "panic", rv,
					"stack", string(debug.Stack()))
				writeError(rec, http.StatusInternalServerError, "internal error")
			}
			s.log.Info("request",
				"request_id", id,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.bytes,
				"remote", r.RemoteAddr,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}()

		next.ServeHTTP(rec, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg, "status": code})
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}

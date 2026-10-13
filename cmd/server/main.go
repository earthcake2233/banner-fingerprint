// Command fingerprint-server serves the banner fingerprinting API.
//
// It also doubles as its own health probe ("-healthcheck <url>"), which keeps
// the runtime image free of a shell and of curl/wget.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/earthcake2233/banner-fingerprint/internal/fingerprint"
	"github.com/earthcake2233/banner-fingerprint/internal/httpapi"
)

// version is injected at build time: -ldflags "-X main.version=..."
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("fingerprint-server", flag.ExitOnError)
	var (
		addr        = fs.String("addr", env("FP_ADDR", ":8080"), "HTTP listen address")
		rulesPath   = fs.String("rules", env("FP_RULES", defaultRulesPath()), "rules file or directory (empty = embedded rules)")
		healthURL   = fs.String("healthcheck", "", "probe this /health URL, exit 0/1, then exit (container healthcheck)")
		logLevel    = fs.String("log-level", env("FP_LOG_LEVEL", "info"), "log level: debug|info|warn|error")
		maxBodyMB   = fs.Int64("max-body-mb", envInt("FP_MAX_BODY_MB", 16), "maximum request body size in MiB")
		watchEvery  = fs.Duration("rules-watch", envDuration("FP_RULES_WATCH", 15*time.Second), "poll interval for hot-reloading the rules file (0 disables)")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("fingerprint-server %s\n", version)
		return nil
	}
	if *healthURL != "" {
		return probe(*healthURL)
	}

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	store, err := fingerprint.NewStore(*rulesPath, logger)
	if err != nil {
		return fmt.Errorf("initialise rules: %w", err)
	}
	logger.Info("starting fingerprint server",
		"version", version, "addr", *addr, "rules", store.Engine().Source(), "rules_count", len(store.Engine().Rules()))

	api := httpapi.New(store, logger, httpapi.Config{MaxBodyBytes: *maxBodyMB << 20, Version: version})
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			if err := store.Reload(); err != nil {
				logger.Error("rules reload failed, keeping previous rules", "err", err)
				continue
			}
			logger.Info("rules reloaded on SIGHUP", "source", store.Engine().Source())
		}
	}()

	if *watchEvery > 0 {
		go store.Watch(ctx.Done(), *watchEvery)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("stopped")
	return nil
}

// probe performs the container healthcheck against our own /health endpoint.
func probe(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	// JSON on stdout keeps the container logs machine-readable.
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

func defaultRulesPath() string {
	for _, p := range []string{"/etc/fingerprint/rules.yaml", "rules/rules.yaml", "../rules/rules.yaml"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "" // fall back to the rule set embedded in the binary
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// Command fingerprint-client reads a local JSON file of raw scan records, sends
// it to the fingerprint server and prints the identification results.
//
// It is the only piece of the system that needs a scanner export on disk, so the
// server can stay stateless and be scaled/deployed on its own.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/earthcake2233/banner-fingerprint/internal/fingerprint"
	"github.com/earthcake2233/banner-fingerprint/internal/jsonutil"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("fingerprint-client", flag.ExitOnError)
	var (
		serverURL = fs.String("url", env("FP_SERVER_URL", "http://127.0.0.1:8080"), "fingerprint server base URL")
		input     = fs.String("input", env("FP_INPUT", "samples/input.json"), `scan JSON file ("-" reads stdin)`)
		format    = fs.String("format", "table", "output format: table|json")
		timeout   = fs.Duration("timeout", 30*time.Second, "per-request timeout")
		retries   = fs.Int("retries", 5, "retries while the server is starting up")
		backoff   = fs.Duration("retry-delay", 2*time.Second, "delay between retries")
		explain   = fs.Bool("explain", false, "ask the server which rule produced each result")
	)
	_ = fs.Parse(os.Args[1:])

	raw, err := readInput(*input)
	if err != nil {
		return err
	}
	inputs, err := jsonutil.DecodeRecords[fingerprint.Input](raw)
	if err != nil {
		return fmt.Errorf("parse %s: %w", *input, err)
	}
	if len(inputs) == 0 {
		return fmt.Errorf("%s contains no records", *input)
	}

	body, err := json.Marshal(inputs)
	if err != nil {
		return err
	}

	url := strings.TrimSuffix(*serverURL, "/") + "/fingerprint"
	if *explain {
		url += "?explain=1"
	}

	resp, err := post(url, body, *timeout, *retries, *backoff)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(payload)))
	}

	results, err := jsonutil.DecodeRecords[fingerprint.Result](payload)
	if err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}

	if *format == "json" {
		out := json.NewEncoder(os.Stdout)
		out.SetEscapeHTML(false)
		out.SetIndent("", "  ")
		return out.Encode(results)
	}
	printTable(results, *explain)
	return nil
}

// post retries while the server is still coming up (its healthcheck may not be
// green yet when the client container starts).
func post(url string, body []byte, timeout time.Duration, retries int, backoff time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt < retries {
			fmt.Fprintf(os.Stderr, "waiting for %s (%v), retry %d/%d\n", url, err, attempt+1, retries)
			time.Sleep(backoff)
		}
	}
	return nil, fmt.Errorf("cannot reach fingerprint server at %s: %w", url, lastErr)
}

func printTable(results []fingerprint.Result, explain bool) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if explain {
		fmt.Fprintln(tw, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONF\tRULE")
	} else {
		fmt.Fprintln(tw, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONF")
	}
	unknown, byProtocol := 0, map[string]int{}
	for _, r := range results {
		byProtocol[r.Protocol]++
		if r.Protocol == fingerprint.Unknown {
			unknown++
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f",
			r.IP, r.Port, r.Protocol, orDash(r.Product), orDash(r.Version), orDash(r.OSHint), r.Confidence)
		if explain {
			fmt.Fprintf(tw, "\t%s", r.RuleID)
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()

	protocols := make([]string, 0, len(byProtocol))
	for p := range byProtocol {
		protocols = append(protocols, p)
	}
	sort.Strings(protocols)
	parts := make([]string, 0, len(protocols))
	for _, p := range protocols {
		parts = append(parts, fmt.Sprintf("%s=%d", p, byProtocol[p]))
	}
	fmt.Printf("\n%d records: %d identified, %d unknown\n", len(results), len(results)-unknown, unknown)
	fmt.Printf("protocols: %s\n", strings.Join(parts, ", "))
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

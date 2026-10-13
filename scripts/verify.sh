#!/usr/bin/env bash
# End-to-end acceptance check for the whole stack, without Docker.
#
# It builds both binaries, starts the server on a throwaway port and drives the
# real HTTP API with curl, printing a PASS/FAIL line with the observed value for
# every check. Deep field-by-field comparison against the reference expectation
# lives in internal/fingerprint/task_example_test.go (run by `go test ./...`).
#
# Usage:  scripts/verify.sh          (server port 18080)
#         PORT=18081 scripts/verify.sh
set -uo pipefail

PORT="${PORT:-18080}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
GO="${GO:-go}"
BIN="$(mktemp -d)"
SRV_PID=""

cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    rm -rf "$BIN"
}
trap cleanup EXIT

pass=0
fail=0
check() { # check <name> <want> <got>
    if [ "$2" = "$3" ]; then
        printf 'PASS  %-44s %s\n' "$1" "$3"
        pass=$((pass + 1))
    else
        printf 'FAIL  %-44s got=%s want=%s\n' "$1" "$3" "$2"
        fail=$((fail + 1))
    fi
}

echo "== 1/5 static checks =="
"$GO" vet ./... && echo "PASS  go vet ./..."
if "$GO" test ./... >"$BIN/test.log" 2>&1; then
    echo "PASS  go test ./..."
else
    echo "FAIL  go test ./..."; cat "$BIN/test.log"
fi

echo "== 2/5 build =="
"$GO" build -o "$BIN/server" ./cmd/server || exit 1
"$GO" build -o "$BIN/client" ./cmd/client || exit 1
echo "PASS  server + client built"

echo "== 3/5 start server on 127.0.0.1:$PORT =="
"$BIN/server" -addr "127.0.0.1:$PORT" -rules rules/rules.yaml >"$BIN/server.log" 2>&1 &
SRV_PID=$!
base="http://127.0.0.1:$PORT"
for _ in $(seq 1 40); do
    curl -fsS "$base/health" >/dev/null 2>&1 && break
    sleep 0.2
done

code() { curl -s -o "$BIN/body" -w '%{http_code}' "$@"; }
count() { grep -o "$1" | wc -l | tr -d ' '; }

echo "== 4/5 API contract =="
check "GET  /health -> 200" 200 "$(code "$base/health")"
check 'health reports "status":"ok"' '"status":"ok"' "$(grep -o '"status":"ok"' "$BIN/body")"
check "GET  /rules -> 200" 200 "$(code "$base/rules")"
check "POST /fingerprint -> 200" 200 "$(code -X POST "$base/fingerprint" -d @samples/input.json)"
check "20 records in -> 20 results" 20 "$(count '"ip":' <"$BIN/body")"
check "exactly 1 unknown result" 1 "$(count '"protocol":"unknown"' <"$BIN/body")"
check "explain=1 adds rule_id to the 19 matched" 19 "$(curl -s -X POST "$base/fingerprint?explain=1" -d @samples/input.json | count '"rule_id":')"
check "reference row 1.2.3.4 verbatim" 1 \
    "$(count '{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}' <"$BIN/body")"
check "reference row 1.2.3.10 verbatim" 1 \
    "$(count '{"ip":"1.2.3.10","port":8080,"protocol":"HTTP","product":"Jetty","version":"9.4.51","os_hint":"","confidence":0.85}' <"$BIN/body")"
check "empty batch -> 200 with []" "[]" "$(curl -s -X POST "$base/fingerprint" -d '[]')"

echo "== 5/5 robustness (nothing may crash the service) =="
check "garbage body -> 400" 400 "$(code -X POST "$base/fingerprint" -d 'not json')"
check "invalid escapes tolerated -> 200" 200 "$(code -X POST "$base/fingerprint" -d @samples/input-messy.txt)"
check "messy batch still yields 5 records" 5 "$(count '"ip":' <"$BIN/body")"
check "GET /fingerprint -> 405" 405 "$(code "$base/fingerprint")"
check "unknown path -> 404" 404 "$(code "$base/nope")"
check "oversized body (17MB) -> 413" 413 \
    "$(head -c 17000000 /dev/zero | tr '\0' 'a' | curl -s -o /dev/null -w '%{http_code}' -X POST "$base/fingerprint" --data-binary @-)"
check 'unknown banner -> "protocol":"unknown"' '"protocol":"unknown"' \
    "$(curl -s -X POST "$base/fingerprint" -d '[{"ip":"9.9.9.9","port":12345,"banner":"QUIT\r\n"}]' | grep -o '"protocol":"[a-z]*"')"
check "unknown result carries confidence 0" '"confidence":0' \
    "$(curl -s -X POST "$base/fingerprint" -d '[{"ip":"9.9.9.9","port":12345,"banner":"QUIT\r\n"}]' | grep -o '"confidence":0')"

burst=200
start=$(date +%s)
for _ in $(seq 1 $burst); do
    curl -s -o /dev/null -X POST "$base/fingerprint" -d @samples/input.json
done
elapsed=$(( $(date +%s) - start ))
echo "INFO  $burst batches (20 records each) served in ${elapsed}s"
check 'health still {"status":"ok"} after burst' '"status":"ok"' "$(curl -s "$base/health" | grep -o '"status":"ok"')"
check "server still identifies after burst" 20 \
    "$(curl -s -X POST "$base/fingerprint" -d @samples/input.json | count '"ip":')"

echo
echo "---------------------------------------------"
printf 'checks passed: %d, failed: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && echo "RESULT: ALL CHECKS PASSED" || echo "RESULT: FAILURES PRESENT"
exit "$fail"

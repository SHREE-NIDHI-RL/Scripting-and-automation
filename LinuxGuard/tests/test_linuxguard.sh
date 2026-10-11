#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/linuxguard.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_code() { local expected="$1"; shift; set +e; "$@" >"$TMP/out" 2>"$TMP/err"; local actual=$?; set -e; [[ "$actual" -eq "$expected" ]] || fail "expected $expected, got $actual: $*"; }
expect_nonzero() { shift; set +e; "$@" >"$TMP/out" 2>"$TMP/err"; local actual=$?; set -e; [[ "$actual" -ne 0 ]] || fail "expected non-zero status: $*"; }
expect_code 0 bash "$SCRIPT" --help
grep -q "Available checks\|Checks:" "$TMP/out" || fail "help output missing checks"
expect_code 64 bash "$SCRIPT" --bad-option
expect_code 64 bash "$SCRIPT" --check
expect_code 64 bash "$SCRIPT" --check unknown
expect_code 64 bash "$SCRIPT" --output
expect_code 64 bash "$SCRIPT"
expect_code 0 bash "$SCRIPT" --check system --output "$TMP/report.json"
[[ -s "$TMP/report.json" ]] || fail "report was not created"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/report.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["sample"] is False
assert data["scan_id"].startswith("linuxguard-")
assert data["checks"][0]["name"] == "system"
assert data["findings"][0]["status"] == "confirmed"
counts = data["summary"]["findings_by_severity"]
actual = {key: sum(1 for item in data["findings"] if item["severity"] == key)
          for key in ("HIGH", "MEDIUM", "LOW", "INFO")}
assert counts == actual
PY
elif command -v python >/dev/null 2>&1; then
    python - "$TMP/report.json" -c 'import json,sys; json.load(open(sys.argv[1]))'
else
    printf 'SKIP: Python unavailable; JSON parser test not run\n'
fi
expect_code 0 bash "$SCRIPT" --check network
expect_code 0 bash "$SCRIPT" --check system --output "$TMP/report with spaces.json"
[[ -s "$TMP/report with spaces.json" ]] || fail "spaced output path was not created"
expect_code 1 bash "$SCRIPT" --check system --output "$TMP/missing/report.json"
expect_code 1 bash "$SCRIPT" --check system --output /proc/linuxguard-test-report.json
mkdir -p "$TMP/shims"
cat > "$TMP/shims/ss" <<'SH'
#!/usr/bin/env bash
printf 'simulated ss failure\n' >&2
exit 7
SH
chmod +x "$TMP/shims/ss"
expect_code 1 env PATH="$TMP/shims:$PATH" bash "$SCRIPT" --check network --output "$TMP/network-failure.json"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/network-failure.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["checks"][0]["status"] == "error"
assert data["findings"][0]["status"] == "error"
assert data["summary"]["error_checks"] == 1
PY
fi
cat > "$TMP/shims/find" <<'SH'
#!/usr/bin/env bash
printf 'simulated permission denied\n' >&2
exit 1
SH
chmod +x "$TMP/shims/find"
expect_code 0 env PATH="$TMP/shims:$PATH" bash "$SCRIPT" --check permissions --output "$TMP/incomplete-scan.json"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/incomplete-scan.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert any(item["title"] == "World-writable scan incomplete" and item["status"] == "unknown"
           for item in data["findings"])
assert not any("No world-writable regular files found" in item["title"]
               for item in data["findings"])
PY
fi
cat > "$TMP/shims/ufw" <<'SH'
#!/usr/bin/env bash
printf 'Status: indeterminate\n'
exit 0
SH
cat > "$TMP/shims/firewall-cmd" <<'SH'
#!/usr/bin/env bash
printf 'running\n'
exit 0
SH
chmod +x "$TMP/shims/ufw" "$TMP/shims/firewall-cmd"
expect_code 0 env PATH="$TMP/shims:$PATH" bash "$SCRIPT" --check firewall --output "$TMP/firewall-fallback.json"
grep -q "firewalld status: active" "$TMP/out" || fail "firewalld fallback was not used"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/firewall-fallback.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert any(item["title"] == "Firewall active" and item["status"] == "confirmed"
           for item in data["findings"])
PY
fi
cat > "$TMP/shims/firewall-cmd" <<'SH'
#!/usr/bin/env bash
printf 'status unavailable\n'
exit 0
SH
chmod +x "$TMP/shims/firewall-cmd"
expect_code 0 env PATH="$TMP/shims:$PATH" bash "$SCRIPT" --check firewall --output "$TMP/firewall-unknown.json"
grep -q "Firewall status could not be determined" "$TMP/out" || fail "inconclusive firewall status was not reported"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/firewall-unknown.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert any(item["title"] == "Firewall status unknown" and item["status"] == "unknown"
           for item in data["findings"])
assert not any(item["title"] == "Firewall inactive" for item in data["findings"])
PY
fi
for check in system ssh firewall network users permissions updates; do
    set +e
    bash "$SCRIPT" --check "$check" >"$TMP/$check.out" 2>"$TMP/$check.err"
    actual=$?
    set -e
    [[ "$actual" -eq 0 || "$actual" -eq 1 || "$actual" -eq 2 ]] || fail "check $check returned unexpected status $actual"
done
printf 'PASS: LinuxGuard CLI and report tests\n'

#!/usr/bin/env bash
set -Eeuo pipefail

readonly TOOL_VERSION="1.0.0"
readonly EXIT_OK=0
readonly EXIT_FINDINGS=2
readonly EXIT_FATAL=1
readonly EXIT_USAGE=64

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH=""
MODE=""
REQUESTED_CHECK=""
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCAN_ID="linuxguard-$(date -u +%Y%m%dT%H%M%SZ)-$$"
WORK_DIR=""
FINDINGS_FILE=""
CHECKS_FILE=""
CHECKS_PERFORMED=0
SKIPPED_CHECKS=0
ERROR_CHECKS=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[31m'; YELLOW=$'\033[33m'; GREEN=$'\033[32m'
    BLUE=$'\033[34m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    RED=""; YELLOW=""; GREEN=""; BLUE=""; CYAN=""; RESET=""
fi

usage() {
    cat <<'EOF'
LinuxGuard 1.0.0 - read-only Linux security auditing tool

Usage:
  ./linuxguard.sh --full [--output report.json]
  ./linuxguard.sh --check NAME [--output report.json]
  ./linuxguard.sh --help

Checks:
  system       System security baseline
  ssh          Effective SSH daemon configuration
  firewall     Firewall state and network exposure
  network      Listening TCP/UDP sockets
  users        UID 0 accounts and sudo capability indicators
  permissions  Sensitive file and bounded world-writable-file audit
  updates      Package updates and service inventory

Examples:
  ./linuxguard.sh --full --output report.json
  ./linuxguard.sh --check ssh
  ./linuxguard.sh --check permissions --output permissions.json

Exit codes:
  0   Audit completed with no HIGH, MEDIUM, or LOW findings
  1   Fatal error (for example, report generation failed)
  2   Audit completed with one or more findings
  64  Invalid arguments or missing option values

The tool is intended for Linux. It never changes configuration, firewall rules,
accounts, permissions, packages, or services. Findings are investigation
indicators, not proof of compromise.
EOF
}

die_usage() { printf '%s\n' "Error: $*" >&2; printf 'Try --help for usage.\n' >&2; exit "$EXIT_USAGE"; }
die_fatal() { printf '%s\n' "${RED}[ERROR]${RESET} $*" >&2; exit "$EXIT_FATAL"; }

sanitize() {
    local value="${1:-}"
    value="${value//$'\t'/ }"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    printf '%s' "$value"
}

log() { printf '%s\n' "$*"; }
pass() { printf '%s\n' "${GREEN}[PASS]${RESET} $*"; }
info() { printf '%s\n' "${BLUE}[INFO]${RESET} $*"; }
warn() { printf '%s\n' "${YELLOW}[WARN]${RESET} $*"; }
error_log() { printf '%s\n' "${RED}[ERROR]${RESET} $*" >&2; }
skipped() { printf '%s\n' "${CYAN}[SKIPPED]${RESET} $*"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

record_check() {
    local check="$1" status="$2" description="$3"
    printf '%s\t%s\t%s\n' "$(sanitize "$check")" "$(sanitize "$status")" "$(sanitize "$description")" >> "$CHECKS_FILE"
    case "$status" in
        performed) CHECKS_PERFORMED=$((CHECKS_PERFORMED + 1)) ;;
        skipped) SKIPPED_CHECKS=$((SKIPPED_CHECKS + 1)) ;;
        error) ERROR_CHECKS=$((ERROR_CHECKS + 1)) ;;
    esac
}

record_finding() {
    local severity="$1" check="$2" title="$3" status="$4" explanation="$5" recommendation="$6"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(sanitize "$severity")" "$(sanitize "$check")" "$(sanitize "$title")" \
        "$(sanitize "$status")" "$(sanitize "$explanation")" "$(sanitize "$recommendation")" >> "$FINDINGS_FILE"
    case "$severity" in
        HIGH) HIGH_COUNT=$((HIGH_COUNT + 1));;
        MEDIUM) MEDIUM_COUNT=$((MEDIUM_COUNT + 1));;
        LOW) LOW_COUNT=$((LOW_COUNT + 1));;
        INFO) INFO_COUNT=$((INFO_COUNT + 1));;
    esac
}

run_system() {
    local distro="unavailable" kernel="unavailable" hostname_value="unavailable"
    local uptime_value="unavailable" user_value="${USER:-unavailable}" root_state="no"
    if [[ -r /etc/os-release ]]; then
        distro="$(. /etc/os-release; printf '%s %s' "${PRETTY_NAME:-${NAME:-Linux}}" "${VERSION_ID:-}")"
    fi
    if command_exists uname; then kernel="$(uname -r 2>/dev/null || printf unavailable)"; fi
    if command_exists hostname; then hostname_value="$(hostname 2>/dev/null || printf unavailable)"; fi
    if command_exists uptime; then uptime_value="$(uptime -p 2>/dev/null || uptime 2>/dev/null || printf unavailable)"; fi
    if [[ "${EUID:-1}" -eq 0 ]]; then root_state="yes"; fi
    record_check system performed "System metadata and root-context baseline"
    info "System: $distro | Kernel: $kernel | Hostname: $hostname_value"
    info "Uptime: $uptime_value | User: $user_value | Running as root: $root_state"
    record_finding INFO system "System baseline collected" confirmed \
        "Distribution, kernel, hostname, uptime, user, and root context were collected where available." \
        "Review the metadata for asset-specific policy; root context alone is not a vulnerability."
}

ssh_value() {
    local key="$1" source="$2"
    awk -v wanted="$key" '
        /^[[:space:]]*#/ { next }
        tolower($1)==tolower(wanted) && value=="" { value=$2 }
        END { if (value != "") print value }
    ' "$source" 2>/dev/null
}

run_ssh() {
    local config="/etc/ssh/sshd_config" permit="" password="" source="unknown" sshd_t_output=""
    if ! command_exists sshd && [[ ! -r "$config" ]]; then
        record_check ssh skipped "SSH daemon and configuration are unavailable"
        skipped "SSH: sshd and /etc/ssh/sshd_config were not available"
        record_finding INFO ssh "SSH audit skipped" skipped "SSH is not installed or configuration is unreadable." "Install/configure SSH only if required."
        return
    fi
    if command_exists sshd; then
        if sshd_t_output="$(sshd -T 2>/dev/null)"; then
            source="sshd -T"
            permit="$(awk '$1=="permitrootlogin" {print $2}' <<<"$sshd_t_output")"
            password="$(awk '$1=="passwordauthentication" {print $2}' <<<"$sshd_t_output")"
        fi
    fi
    if [[ "$source" == "unknown" && -r "$config" ]]; then
        source="raw sshd_config (includes/effective order may not be resolved)"
        permit="$(ssh_value PermitRootLogin "$config")"
        password="$(ssh_value PasswordAuthentication "$config")"
        if [[ -z "$permit" ]]; then permit="unknown"; fi
        if [[ -z "$password" ]]; then password="unknown"; fi
    fi
    record_check ssh performed "SSH configuration audit using $source"
    info "SSH source: $source"
    case "${permit,,}" in
        no) pass "SSH PermitRootLogin: no"; record_finding INFO ssh "Root SSH login disabled" confirmed "Effective PermitRootLogin is no." "Keep direct root login disabled and use controlled privilege escalation.";;
        yes|prohibit-password|without-password) warn "SSH PermitRootLogin: $permit"; record_finding HIGH ssh "Root SSH login is permitted" confirmed "Effective PermitRootLogin is $permit." "Disable direct root login unless a documented exception is required.";;
        *) warn "SSH PermitRootLogin: unknown"; record_finding INFO ssh "Root SSH login setting unknown" unknown "The effective value could not be established." "Review sshd -T and included configuration manually.";;
    esac
    case "${password,,}" in
        no) pass "SSH PasswordAuthentication: no"; record_finding INFO ssh "SSH password authentication disabled" confirmed "Effective PasswordAuthentication is no." "Prefer strong key-based authentication with account controls.";;
        yes) warn "SSH PasswordAuthentication: yes"; record_finding MEDIUM ssh "SSH password authentication enabled" confirmed "Effective PasswordAuthentication is yes." "Consider key-based authentication and rate limiting based on operational needs.";;
        *) warn "SSH PasswordAuthentication: unknown"; record_finding INFO ssh "Password authentication setting unknown" unknown "The effective value could not be established." "Review sshd -T and included configuration manually.";;
    esac
}

run_network() {
    local sockets=""
    if ! command_exists ss; then
        record_check network skipped "ss is unavailable"
        skipped "Network: ss is unavailable; listening sockets could not be inspected"
        record_finding INFO network "Listening socket audit skipped" skipped "The ss utility was not available." "Install iproute2 or inspect sockets with an approved local tool."
        return
    fi
    sockets="$(ss -H -ltnup 2>/dev/null || true)"
    record_check network performed "Listening TCP and UDP socket inventory"
    if [[ -n "$sockets" ]]; then
        info "Listening sockets (addresses and ports):"
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then printf '  %s\n' "$line"; fi
        done <<<"$sockets"
        record_finding INFO network "Listening sockets found" confirmed "Listening endpoints were inventoried; exposure is not inherently malicious." "Review each externally bound service against the host's intended role."
    else
        pass "No listening TCP/UDP sockets were returned by ss"
        record_finding INFO network "No listening sockets reported" confirmed "ss returned no listening TCP/UDP sockets." "Recheck if services are expected on this host."
    fi
}

run_firewall() {
    local status="unknown" tool="none" detail=""
    if command_exists ufw; then
        tool="ufw"
        detail="$(ufw status 2>&1 || true)"
        grep -qi '^status: active' <<<"$detail" && status="active"
        grep -qi '^status: inactive' <<<"$detail" && status="inactive"
    elif command_exists firewall-cmd; then
        tool="firewalld"
        detail="$(firewall-cmd --state 2>&1 || true)"
        grep -qx 'running' <<<"$detail" && status="active"
        grep -Eqi 'not running|inactive|failed' <<<"$detail" && status="inactive"
    fi
    if [[ "$tool" == "none" ]]; then
        record_check firewall skipped "No supported firewall management tool found"
        skipped "Firewall: UFW and firewalld were not available"
        record_finding INFO firewall "Firewall status unavailable" unknown "Neither UFW nor firewalld was detected." "Verify the host firewall with its platform-specific controls."
    else
        record_check firewall performed "$tool firewall status"
        info "$tool status: $status"
        case "$status" in
            active) pass "Firewall appears active"; record_finding INFO firewall "Firewall active" confirmed "$tool reported an active firewall." "Review rules for least privilege and required exposure.";;
            inactive) warn "Firewall appears inactive"; record_finding MEDIUM firewall "Firewall inactive" confirmed "$tool reported an inactive firewall." "Enable a host firewall according to the host's approved policy.";;
            *) warn "Firewall status could not be determined"; record_finding INFO firewall "Firewall status unknown" unknown "The detected tool did not provide a recognized state: $detail" "Inspect firewall state manually; do not assume it is active.";;
        esac
    fi
}

run_users() {
    local uid0="" extra="" group_info="" sudoers=""
    if [[ ! -r /etc/passwd ]]; then
        record_check users error "Cannot read /etc/passwd"
        error_log "Users: /etc/passwd is unreadable"
        record_finding INFO users "User audit failed" error "The passwd database could not be read." "Run with an account permitted to inspect local account metadata."
        return
    fi
    uid0="$(awk -F: '$3 == 0 {print $1}' /etc/passwd)"
    extra="$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)"
    record_check users performed "UID 0 accounts and sudo capability indicators"
    info "UID 0 accounts: $(tr '\n' ' ' <<<"$uid0")"
    if [[ -n "$extra" ]]; then
        warn "Additional UID 0 account(s): $(tr '\n' ' ' <<<"$extra")"
        record_finding HIGH users "Additional UID 0 account detected" confirmed "Accounts other than root have UID 0: $(tr '\n' ' ' <<<"$extra")." "Validate each account and remove or restrict undocumented privileged identities."
    else
        pass "Only the root account has UID 0"
        record_finding INFO users "No additional UID 0 accounts" confirmed "The local passwd database contains only root with UID 0." "Continue monitoring privileged account changes."
    fi
    if getent group sudo >/dev/null 2>&1; then group_info="$(getent group sudo)"; fi
    if getent group wheel >/dev/null 2>&1; then group_info="${group_info:+$group_info; }$(getent group wheel)"; fi
    if [[ -n "$group_info" ]]; then
        info "Sudo-capable group entries (membership is an indicator, not proof of effective access): $group_info"
    fi
    if [[ -r /etc/sudoers ]]; then sudoers="readable"; else sudoers="unreadable or absent"; fi
    record_finding INFO users "Sudo capability reviewed" confirmed "Sudo groups and /etc/sudoers availability were checked; sudoers is $sudoers." "Review effective sudo policy and group membership against least privilege."
}

audit_file() {
    local path="$1" mode owner group
    if [[ -L "$path" ]]; then
        record_finding LOW permissions "Sensitive path is a symbolic link" confirmed "$path is a symbolic link; target ownership and permissions require separate review." "Validate the link target and ensure it cannot redirect privileged operations."
        return
    fi
    if [[ ! -e "$path" ]]; then
        record_finding INFO permissions "Sensitive file unavailable" skipped "$path does not exist on this host." "Confirm whether the component is intentionally absent."
        return
    fi
    if ! mode="$(stat -c '%a' -- "$path" 2>/dev/null)" || ! owner="$(stat -c '%U' -- "$path" 2>/dev/null)" || ! group="$(stat -c '%G' -- "$path" 2>/dev/null)"; then
        record_finding INFO permissions "Sensitive file metadata unavailable" unknown "Could not inspect metadata for $path." "Review ownership and mode with permitted tools."
        return
    fi
    info "$path: mode $mode, owner $owner:$group"
    case "$path" in
        /etc/shadow|/etc/gshadow)
            if (( (8#$mode & 004) != 0 )) ||
               { (( (8#$mode & 040) != 0 )) && [[ "$owner" != "root" || "$group" != "shadow" ]]; } ||
               (( (8#$mode & 022) != 0 )); then
                warn "$path is readable by group or others"
                record_finding HIGH permissions "Sensitive credential file is too readable" confirmed "$path mode $mode permits non-owner read access." "Restrict access to root and the approved shadow group."
            else
                record_finding INFO permissions "Sensitive credential file permissions acceptable" confirmed "$path does not expose read access to group/others." "Keep ownership and permissions tightly controlled."
            fi;;
        *)
            if (( (8#$mode & 022) != 0 )); then
                warn "$path is writable by group or others"
                record_finding HIGH permissions "Sensitive file is writable by group or others" confirmed "$path mode $mode permits non-owner write access." "Restrict write access to trusted administrators."
            else
                record_finding INFO permissions "Sensitive file is not group/other writable" confirmed "$path mode $mode does not permit group/other write access." "Maintain restrictive ownership and permissions."
            fi;;
    esac
}

run_permissions() {
    local path dir result=""
    record_check permissions performed "Sensitive file metadata and bounded world-writable scan"
    for path in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config; do audit_file "$path"; done
    for dir in /tmp /var/tmp /etc; do
        if [[ -d "$dir" && -r "$dir" ]]; then
            if command_exists find; then
                result="$(find "$dir" -xdev -type f -perm -0002 -print 2>/dev/null | head -n 100 || true)"
                if [[ -n "$result" ]]; then
                    warn "World-writable files found under bounded scan $dir (up to 100 shown)"
                    while IFS= read -r path; do
                        if [[ -n "$path" ]]; then printf '  %s\n' "$path"; fi
                    done <<<"$result"
                    record_finding MEDIUM permissions "World-writable files found" confirmed "The bounded scan found one or more world-writable regular files under $dir." "Review each file's purpose and remove unnecessary world-write access."
                else
                    pass "No world-writable regular files found under $dir"
                fi
            fi
        else
            record_finding INFO permissions "Bounded directory scan skipped" skipped "$dir is unavailable or unreadable." "Review the directory with appropriate permissions if it is in scope."
        fi
    done
}

run_updates() {
    local manager="none" updates="" services=""
    if command_exists apt-get; then manager="apt"
    elif command_exists dnf; then manager="dnf"
    elif command_exists yum; then manager="yum"; fi
    if [[ "$manager" == "none" ]]; then
        record_check updates skipped "No supported package manager found"
        skipped "Updates: APT, DNF, and YUM were unavailable"
        record_finding INFO updates "Update audit skipped" unknown "No supported package manager was detected." "Check updates using the operating system's package tooling."
    else
        record_check updates performed "$manager package metadata and service inventory"
        case "$manager" in
            apt) if command_exists apt; then updates="$(apt list --upgradable 2>/dev/null | sed '1d' | head -n 50 || true)"; fi;;
            dnf) updates="$(dnf -q check-update --assumeno 2>/dev/null || true)";;
            yum) updates="$(yum -q check-update 2>/dev/null || true)";;
        esac
        if [[ -n "$updates" ]]; then
            warn "Potential package updates were reported by $manager (indexes were not refreshed)"
            record_finding LOW updates "Package updates may be available" confirmed "The package manager reported update candidates using local/current metadata." "Review and apply approved security updates; verify metadata freshness."
        else
            info "No package updates were reported, or update information was unavailable/stale"
            record_finding INFO updates "Package update state inconclusive" unknown "No update candidates were returned; this does not prove the system is fully patched." "Check metadata freshness and consult the distribution's security advisories."
        fi
    fi
    if command_exists systemctl; then
        services="$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | head -n 100 || true)"
        info "Running services (up to 100):"
        if [[ -n "$services" ]]; then printf '%s\n' "$services"; fi
        record_finding INFO updates "Running services inventoried" confirmed "Running services were listed where systemd is available; service necessity and exposure require local context." "Review enabled and externally reachable services against the host baseline."
    else
        record_finding INFO updates "Service inventory unavailable" skipped "systemctl is not available; service state was not inventoried." "Use the platform's service manager to review running and enabled services."
    fi
}

generate_report() {
    local end_ts="$1"
    command_exists python3 || command_exists python || return 1
    local py
    if command_exists python3; then py=python3; else py=python; fi
    "$py" - "$OUTPUT_PATH" "$FINDINGS_FILE" "$CHECKS_FILE" "$START_TS" "$end_ts" "$SCAN_ID" \
        "$CHECKS_PERFORMED" "$SKIPPED_CHECKS" "$ERROR_CHECKS" "$HIGH_COUNT" "$MEDIUM_COUNT" "$LOW_COUNT" "$INFO_COUNT" <<'PY'
import json, os, sys
out, findings_path, checks_path, start, end, scan_id = sys.argv[1:7]
counts = dict(zip(("performed", "skipped", "errors", "HIGH", "MEDIUM", "LOW", "INFO"),
                  map(int, sys.argv[7:14])))
findings = []
with open(findings_path, encoding="utf-8") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 6:
            severity, check, title, status, explanation, recommendation = parts
            findings.append({"severity": severity, "check": check, "title": title,
                             "status": status, "explanation": explanation,
                             "recommendation": recommendation})
checks = []
with open(checks_path, encoding="utf-8") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 3:
            checks.append({"name": parts[0], "status": parts[1], "description": parts[2]})
os_release = {}
try:
    with open("/etc/os-release", encoding="utf-8") as fh:
        for line in fh:
            if "=" in line:
                key, value = line.rstrip().split("=", 1)
                os_release[key] = value.strip('"')
except OSError:
    pass
report = {
    "schema_version": "1.0",
    "sample": False,
    "scan_id": scan_id,
    "audit_start": start,
    "audit_end": end,
    "tool": {"name": "LinuxGuard", "version": "1.0.0"},
    "system": {
        "platform": sys.platform,
        "distribution": os_release.get("PRETTY_NAME", os_release.get("NAME", "unavailable")),
        "kernel": os.uname().release if hasattr(os, "uname") else "unavailable",
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unavailable",
        "current_user": os.environ.get("USER", "unavailable"),
        "running_as_root": hasattr(os, "geteuid") and os.geteuid() == 0,
    },
    "checks": checks,
    "findings": findings,
    "summary": {"checks_performed": counts["performed"], "skipped_checks": counts["skipped"],
                "error_checks": counts["errors"],
                "findings_by_severity": {k: counts[k] for k in ("HIGH", "MEDIUM", "LOW", "INFO")}},
    "disclaimer": "Automated findings are indicators for investigation, not proof of compromise.",
}
parent = os.path.dirname(os.path.abspath(out))
if parent and not os.path.isdir(parent):
    raise SystemExit("output directory does not exist")
try:
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=True)
        fh.write("\n")
except OSError as exc:
    raise SystemExit(f"could not write JSON report: {exc}")
PY
}

summary() {
    log ""
    log "LinuxGuard summary"
    log "  Checks performed: $CHECKS_PERFORMED"
    log "  Skipped checks:   $SKIPPED_CHECKS"
    log "  Check errors:     $ERROR_CHECKS"
    log "  Findings: HIGH=$HIGH_COUNT MEDIUM=$MEDIUM_COUNT LOW=$LOW_COUNT INFO=$INFO_COUNT"
    if [[ -n "$OUTPUT_PATH" ]]; then log "  Report: $OUTPUT_PATH"; fi
}

parse_args() {
    [[ "$#" -eq 0 ]] && { usage; exit "$EXIT_USAGE"; }
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --help|-h) usage; exit 0;;
            --full) [[ -z "$MODE" ]] || die_usage "choose --full or --check, not both"; MODE="full"; shift;;
            --check) [[ "$#" -ge 2 ]] || die_usage "--check requires a check name"; [[ -z "$MODE" ]] || die_usage "choose --full or --check, not both"; MODE="check"; REQUESTED_CHECK="$2"; shift 2;;
            --output) [[ "$#" -ge 2 ]] || die_usage "--output requires a path"; OUTPUT_PATH="$2"; shift 2;;
            --) shift; [[ "$#" -eq 0 ]] || die_usage "unexpected arguments after --";;
            *) die_usage "unknown option: $1";;
        esac
    done
    [[ -n "$MODE" ]] || die_usage "an operation is required"
    if [[ "$MODE" == "check" && ! "$REQUESTED_CHECK" =~ ^(system|ssh|firewall|network|users|permissions|updates)$ ]]; then
        die_usage "unknown check name: $REQUESTED_CHECK"
    fi
}

main() {
    parse_args "$@"
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/linuxguard.XXXXXX")" || die_fatal "could not create temporary workspace"
    trap 'rm -rf -- "$WORK_DIR"' EXIT
    FINDINGS_FILE="$WORK_DIR/findings.tsv"; CHECKS_FILE="$WORK_DIR/checks.tsv"
    : > "$FINDINGS_FILE"; : > "$CHECKS_FILE"
    if [[ "$MODE" == "full" ]]; then
        run_system; run_ssh; run_firewall; run_network; run_users; run_permissions; run_updates
    else
        "run_$REQUESTED_CHECK"
    fi
    if [[ -n "$OUTPUT_PATH" ]]; then
        [[ "$OUTPUT_PATH" != */* || -d "$(dirname -- "$OUTPUT_PATH")" ]] || die_fatal "output directory does not exist: $(dirname -- "$OUTPUT_PATH")"
        generate_report "$(date -u +%Y-%m-%dT%H:%M:%SZ)" || die_fatal "JSON report generation requires Python and a writable output path"
    fi
    summary
    if (( HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT > 0 )); then exit "$EXIT_FINDINGS"; fi
    exit "$EXIT_OK"
}

main "$@"

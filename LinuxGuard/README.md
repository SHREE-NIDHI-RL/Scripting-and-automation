# LinuxGuard

LinuxGuard is a read-only Bash security auditing tool for Blue Team baseline
reviews. It collects host context, inspects SSH and firewall posture, inventories
network exposure, reviews privileged accounts and sensitive-file permissions,
checks locally available package metadata, and produces a machine-readable JSON
report. Automated findings are indicators for investigation, not proof of
compromise.

## Problem and objectives

Small Linux hosts often lack a consistent, repeatable security review. LinuxGuard
provides a safe first-pass audit that:

* uses only read-only inspection commands;
* distinguishes confirmed findings, unknown results, skipped checks, and errors;
* avoids exposing password hashes or file contents;
* works without root wherever the operating system permits; and
* returns an exit status suitable for scripts and CI.

## Features

| Check | What it reviews |
| --- | --- |
| `system` | Distribution, kernel, hostname, uptime, current user, and root context |
| `ssh` | Effective `sshd -T` values when possible, otherwise cautious configuration parsing for `PermitRootLogin` and `PasswordAuthentication` |
| `firewall` | UFW or firewalld state |
| `network` | Listening TCP/UDP sockets from `ss` |
| `users` | UID 0 accounts, sudo-capable group indicators, and sudoers availability |
| `permissions` | Metadata for sensitive files and bounded world-writable scans under `/tmp`, `/var/tmp`, and `/etc` |
| `updates` | APT, DNF, or YUM update candidates using existing metadata, plus systemd running-service inventory |

## Architecture

[`linuxguard.sh`](./linuxguard.sh) parses arguments, creates a temporary
workspace, runs one or more independent check functions, records normalized
findings, prints a terminal summary, and optionally invokes the Python standard
library only to serialize valid JSON. It does not refresh package indexes,
change services, write configuration, alter users, or change permissions.

## Prerequisites and supported environments

LinuxGuard is a Linux Bash program. It requires Bash 4 or newer and standard
utilities such as `awk`, `date`, `find`, `mktemp`, `stat`, and `uname`. Python 3
(or `python`) is required only when `--output` is used.

Optional utilities improve coverage: `sshd`, `ss`, `ufw`, `firewall-cmd`,
`getent`, `systemctl`, `apt`/`apt-get`, `dnf`, and `yum`. LinuxGuard does not
install missing utilities or refresh package indexes.

The supported target is a normal Linux installation, including current
Debian/Ubuntu and Fedora/RHEL-compatible distributions. It also runs on many
minimal/container systems, but checks may be skipped when utilities or files are
absent. It does not assume systemd, UFW, APT, a particular SSH installation, or
a particular package manager.

Native Windows PowerShell and `cmd.exe` are not supported execution environments.
Windows users should run LinuxGuard inside Ubuntu WSL or a Linux virtual machine.
WSL may expose Windows-integrated networking and services rather than a
conventional Linux host, so socket, service, firewall, and package results
should be interpreted in that context.

## Installation

```bash
git clone https://github.com/SHREE-NIDHI-RL/Scripting-and-automation.git
cd Scripting-and-automation/LinuxGuard
chmod +x linuxguard.sh tests/test_linuxguard.sh
```

No external packages are installed by the tool.

## Usage

```text
./linuxguard.sh --help
./linuxguard.sh --full
./linuxguard.sh --output report.json       # output requires --full or --check
./linuxguard.sh --full --output report.json
./linuxguard.sh --check ssh
./linuxguard.sh --check firewall
./linuxguard.sh --check users
./linuxguard.sh --check permissions
./linuxguard.sh --check updates
./linuxguard.sh --check network
./linuxguard.sh --check system
```

Running without arguments prints concise usage and returns exit code 64.
`--check` runs only the selected feature group. The report path's parent
directory must already exist and be writable. For example:

```bash
mkdir -p "$HOME/linuxguard-reports"
./linuxguard.sh --full --output "$HOME/linuxguard-reports/full.json"
```

## Permissions

LinuxGuard is designed to run as an ordinary user. Basic system metadata,
`/etc/passwd`, and many command outputs normally work without elevation.
Reading sensitive metadata, enumerating socket process owners, querying effective
firewall state, reading sudo policy, or inspecting protected directories may
require root or additional group permissions on some systems.

Do not run the entire audit as root by default. If a check is permission-limited,
LinuxGuard records an `unknown`, `skipped`, or `error` result instead of treating
missing data as safe. It never prints password hashes, private keys, or sensitive
file contents.

## Example terminal output

```text
[INFO] System: Ubuntu 24.04 LTS 24.04 | Kernel: 6.8.0 | Hostname: audit-host
[INFO] Uptime: up 2 hours | User: analyst | Running as root: no
[PASS] SSH PermitRootLogin: no
[WARN] SSH PasswordAuthentication: yes
[INFO] Listening sockets (addresses and ports):
  tcp LISTEN 0 128 0.0.0.0:22 ...

LinuxGuard summary
  Checks performed: 7
  Skipped checks:   0
  Check errors:     0
  Findings: HIGH=0 MEDIUM=1 LOW=0 INFO=12
  Report: report.json
```

Colours are used only for interactive terminals. Set `NO_COLOR=1` for plain
output.

## Understanding the output

`[PASS]` means the reported condition was confirmed acceptable. `[WARN]` means
the condition needs review. `HIGH`, `MEDIUM`, and `LOW` are finding severities
and affect the process exit status. `INFO` is contextual or informational.
`[SKIPPED]` means a check could not be attempted because a required component
was absent. `UNKNOWN` means the state could not be established, while `ERROR`
means an operation failed. Unknown, skipped, and error results are not passes.

Findings are indicators for investigation, not proof of compromise. A listening
service is not automatically malicious, and membership in a sudo-capable group
does not alone prove effective sudo access.

## JSON report

[`docs/sample-report.json`](./docs/sample-report.json) is illustrative sample
data, not a claim about a real host. Reports contain `schema_version`, `sample`,
`scan_id`, audit timestamps, tool and system metadata, check statuses, findings,
severity counts, explanations, and recommendations. Python's JSON encoder
escapes unusual characters safely. Reports are written exactly to the path
provided to `--output`; LinuxGuard will not create a missing parent directory.
Validate a generated report with:

```bash
python3 -m json.tool "$HOME/linuxguard-reports/full.json" >/dev/null
```

The report includes separate check statuses and finding statuses, so skipped,
unknown, and failed operations remain visible when other checks succeed.

## Severity classification

* **HIGH**: a direct privilege or credential exposure, such as an unexpected UID
  0 account or unsafe access to shadow credentials.
* **MEDIUM**: a meaningful hardening or exposure concern, such as inactive
  firewall protection, password SSH authentication, or world-writable files.
* **LOW**: a review-worthy hygiene concern, such as possible package updates or
  a sensitive path represented by a symbolic link.
* **INFO**: contextual, confirmed-safe, unknown, or skipped result. Unknown and
  skipped results are never counted as passes.

## Errors and exit codes

* `0` — completed with no HIGH, MEDIUM, or LOW findings;
* `1` — fatal error, such as inability to create the temporary workspace or
  generate a requested report;
* `2` — completed with one or more HIGH, MEDIUM, or LOW findings;
* `64` — invalid arguments or a missing option value.

Individual optional commands may be unavailable or permission-limited. LinuxGuard
records that state instead of treating command failure as a successful check.

## Testing and Validation

LinuxGuard includes a Bash test suite to verify command-line behavior, input
validation, and report generation. Run the tests before using the tool or when
checking changes to the project.

**Run the automated tests:**

```bash
bash tests/test_linuxguard.sh
```

**Run LinuxGuard manually:**

```bash
bash linuxguard.sh --help
bash linuxguard.sh --check system
bash linuxguard.sh --full --output /tmp/linuxguard-report.json
```

The automated test suite checks the behaviors implemented in
[`tests/test_linuxguard.sh`](./tests/test_linuxguard.sh), while the manual
commands allow you to inspect the tool's terminal output and generated security
audit reports. The commands above are intended to be run from inside the
`LinuxGuard/` directory after cloning the repository.

The test suite does not prove that every security vulnerability can be detected.
Actual audit results depend on the host system, available utilities, permissions,
and supported Linux distribution. The tests use temporary output only and do
not modify host configuration. If ShellCheck is already installed, run:

```bash
shellcheck linuxguard.sh tests/test_linuxguard.sh
```

ShellCheck is optional and is not installed automatically.

## Troubleshooting

* **Missing command or skipped check:** install the relevant distribution
  package through your normal administration process. LinuxGuard does not
  install dependencies.
* **SSH is skipped or UNKNOWN:** SSH may not be installed, its configuration may
  be absent/unreadable, or `sshd -T` may not be usable. Review the effective
  configuration with an administrator.
* **Firewall status is unavailable:** verify UFW, firewalld, or another
  platform firewall manually. An absent firewall utility is not treated as an
  active firewall.
* **Updates are UNKNOWN:** metadata may be stale/unavailable, or the package
  manager may not be APT, DNF, or YUM. LinuxGuard does not silently refresh it.
* **No service inventory:** systems without `systemctl` are supported, but
  service state must be checked with that platform's service manager.
* **Output path errors:** create the parent directory and confirm write access;
  do not use `/proc`, `/sys`, or another virtual read-only filesystem.
* **WSL differences:** WSL may not represent a standalone Linux firewall, init
  system, or network namespace. Use a Linux VM or native Linux host when those
  controls are the subject of the audit.

## Safety, privacy, and limitations

LinuxGuard does not print password hashes, private keys, or sensitive file
contents. Socket and service names can still reveal operational details, so
store reports appropriately. A raw `sshd_config` fallback cannot always resolve
all include files or conditional `Match` blocks; it explicitly reports the
limitation. Package update status depends on local metadata and is not a
substitute for vendor advisories. Permission restrictions can prevent
LinuxGuard from establishing a state.

LinuxGuard is strictly read-only with respect to the audited host. It does not
change firewall rules, SSH configuration, users, permissions, packages, service
state, or package indexes. It is a baseline aid, not a replacement for
configuration management, vulnerability management, vendor advisories, or a
full incident-response investigation.

Future improvements could add distro-specific advisory integration, configurable
bounded scan directories, richer systemd enabled-service analysis, and signed
report delivery. These are not part of the current implementation.

# Scripting and Automation

This repository contains practical cybersecurity and automation tools built
with Bash and Python. I am using it to learn by building small utilities that
inspect systems, help explain network behavior, and automate repeatable
security-related tasks without changing the environment being examined.

The projects are intentionally focused rather than enterprise platforms. Each
one is self-contained and has its own documentation, tests, and usage
instructions.

## Projects

### LinuxGuard

[LinuxGuard](./LinuxGuard/) is a read-only Linux security auditing tool written
in Bash. It reviews:

- System baseline information, including distribution, kernel, hostname,
  uptime, user, and root context
- SSH settings such as `PermitRootLogin` and `PasswordAuthentication`
- UFW or firewalld status
- Listening TCP and UDP sockets
- UID 0 accounts, sudo-capable group indicators, and sudo policy availability
- Sensitive file ownership and permissions, plus bounded world-writable scans
- APT, DNF, or YUM update information and running services where supported

LinuxGuard can print a terminal summary and generate timestamped JSON reports.
It distinguishes confirmed findings from skipped, unknown, and failed checks,
and does not modify SSH, firewall, user, permission, package, or service
configuration.

Read the full guide in [LinuxGuard/README.md](./LinuxGuard/README.md).

### NetScope

[NetScope](./NetScope/) is a read-only Python CLI tool for local network
information and diagnostics. It can:

- Collect system and local network information where the operating system
  exposes it
- Resolve explicitly supplied hostnames to IPv4 and IPv6 addresses
- Test TCP connectivity to one explicitly supplied hostname and port
- Export summary, DNS, connectivity, and full diagnostic results as JSON

NetScope uses Python's standard library at runtime and includes platform-aware
handling for Windows, Linux, and WSL. Gateway, resolver, interface, and address
information can vary by platform and permissions, so unavailable data is
reported rather than invented.

Read the full guide in [NetScope/README.md](./NetScope/README.md).

## Repository structure

```text
Scripting-and-automation/
├── README.md
├── LinuxGuard/
│   ├── linuxguard.sh
│   ├── README.md
│   ├── LICENSE
│   ├── tests/
│   │   └── test_linuxguard.sh
│   └── docs/
│       └── sample-report.json
└── NetScope/
    ├── netscope.py
    ├── README.md
    ├── requirements.txt
    ├── tests/
    │   └── test_netscope.py
    └── reports/
        └── sample_report.json
```

## Technologies used

- Bash
- Python
- Python standard library
- Git
- Linux and WSL
- Windows support for NetScope
- JSON

## Getting started

Clone the repository, then choose a project. The projects are standalone and
have separate prerequisites and commands:

```bash
git clone https://github.com/SHREE-NIDHI-RL/Scripting-and-automation.git
cd Scripting-and-automation
```

Continue with:

- [LinuxGuard setup and usage](./LinuxGuard/README.md)
- [NetScope setup and usage](./NetScope/README.md)

LinuxGuard is intended to run on Linux, including a suitable Ubuntu WSL
environment or Linux virtual machine. NetScope targets Python 3.9 or newer on
Windows, Linux, and WSL.

## Testing

Each project includes its own tests.

Run LinuxGuard's Bash test suite from the repository root:

```bash
bash LinuxGuard/tests/test_linuxguard.sh
```

Run NetScope's compile check and Python `unittest` suite:

```bash
python -m py_compile NetScope/netscope.py
python -m unittest discover -s NetScope/tests -v
```

The test suites use temporary files and mocks where appropriate. They are not a
replacement for testing on the systems and networks where the tools will
actually be used. No continuous integration or CI/CD configuration is included
in this repository.

## Limitations and responsible use

These projects are educational and diagnostic utilities, not complete enterprise
security platforms. They do not guarantee that a system is secure or that every
vulnerability, exposed service, or network condition will be detected.

Results depend on the operating system, available commands, permissions,
configuration, DNS behavior, package metadata, and current network environment.
Some checks may be skipped or reported as unknown when information is
unavailable. Review findings in context and only test systems and network
endpoints that you are authorized to inspect.

Both tools are designed to be read-only. LinuxGuard does not remediate audit
findings, and NetScope does not change routes, DNS, firewall settings,
interfaces, or services. Reports can contain hostnames, addresses, platform
details, or requested endpoints, so review them before sharing publicly.

## Future improvements

Future work may include expanding the test fixtures, improving platform-specific
information collection, adding carefully scoped report options, and refining
the tools' handling of incomplete or permission-limited results. Any new
features should preserve the projects' focused, read-only behavior.

# NetScope

NetScope is a cross-platform, read-only Python CLI for local network
information, DNS resolution, one explicitly requested TCP connectivity test, and
JSON diagnostic reports.

## Features

* Local hostname, operating-system, Python, interface, address, gateway, and
  resolver information where the platform exposes it.
* IPv4 and IPv6 DNS lookup using Python's `socket` facilities.
* One finite TCP connection test for the exact hostname and port supplied by the
  user.
* Human-readable JSON output for summary, DNS, connectivity, and full reports.
* Standard-library runtime only; no third-party dependencies are required.

## Supported platforms and limitations

NetScope targets Python 3.9+ on Windows, Linux, and WSL. Gateway and resolver
discovery is platform-dependent. Linux reads `/proc/net/route` and
`/etc/resolv.conf`; Windows uses the `route` command for the default gateway
and intentionally reports resolver configuration as unavailable rather than
parsing localized output. Interface enumeration and local address discovery are
best effort.

Local addresses are those returned for the local hostname; they are not a
guarantee of every address assigned to every interface. Results depend on the
current machine, operating system, DNS configuration, permissions, and network
connectivity. WSL may expose Windows-integrated networking rather than a
standalone Linux network namespace.

## Installation

Clone the repository and enter the project:

```bash
git clone https://github.com/SHREE-NIDHI-RL/Scripting-and-automation.git
cd Scripting-and-automation/NetScope
python --version
```

No package installation is required. `requirements.txt` documents the
standard-library-only runtime.

## Usage

Run these commands from inside `NetScope/`:

```bash
python netscope.py --help
python netscope.py summary
python netscope.py dns example.com
python netscope.py connectivity example.com --port 443
python netscope.py summary --json reports/summary.json
python netscope.py full --json reports/full.json
```

The connectivity command accepts `--timeout SECONDS` as an optional positive
finite timeout. It tests only the specified hostname and port; NetScope does
not scan ports, discover hosts, exploit services, or change network settings.

## Example output

```text
{
  "operation": "dns",
  "target": "example.com",
  "results": {
    "status": "available",
    "value": {
      "ipv4": ["93.184.216.34"],
      "ipv6": []
    }
  }
}
```

Addresses are examples only and vary by resolver and network.

## JSON reports

Use `--json PATH` to save a valid report. Parent directories are created when
possible, and NetScope prints a success message only after the file is written.
Reports contain a UTC timestamp, tool/version, platform metadata, operation,
structured results, collection errors, and a diagnostic disclaimer.

An illustrative report is available at
[`reports/sample_report.json`](./reports/sample_report.json). It contains sample
values and is not a report from a real machine.

Validate a report with:

```bash
python -m json.tool reports/full.json >/dev/null
```

Do not save reports containing machine information into a public repository.

## Testing

Run the built-in unittest suite from the repository root:

```bash
python -m py_compile NetScope/netscope.py
python -m unittest discover -s NetScope/tests -v
python -m json.tool NetScope/reports/sample_report.json >/dev/null
```

The tests use mocks for DNS, sockets, platform data, and optional command
failures. They do not require internet access and do not change network
configuration.

## Error handling and exit codes

Successful commands return exit code `0`. Invalid subcommands, arguments, ports,
timeouts, DNS errors, connectivity failures, and report-write failures produce
understandable diagnostics and a nonzero exit code. A connectivity or DNS
failure is represented in JSON when a report is requested; the CLI still
returns `0` after successfully collecting and writing that diagnostic result.
This distinguishes “the diagnostic ran and found a failure” from “NetScope
could not process the command or save the report.”

## Security and privacy

NetScope is read-only. It does not change interfaces, routes, DNS, firewalls,
or services. TCP tests are limited to explicitly supplied endpoints. Reports
may contain hostnames, local addresses, platform details, and requested
endpoints, so protect them as operational data and avoid publishing them
without review. DNS resolution alone is not a safety or maliciousness verdict.

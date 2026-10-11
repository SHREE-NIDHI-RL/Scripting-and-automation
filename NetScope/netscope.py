#!/usr/bin/env python3
"""NetScope: read-only local network information and diagnostics."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

TOOL_NAME = "NetScope"
TOOL_VERSION = "1.0.0"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def result(status: str, value: Any = None, error: Optional[str] = None) -> dict[str, Any]:
    item: dict[str, Any] = {"status": status}
    if value is not None:
        item["value"] = value
    if error:
        item["error"] = error
    return item


def unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def collect_system_info() -> dict[str, Any]:
    """Collect system identity without assuming a particular operating system."""
    values: dict[str, Any] = {}
    errors: list[str] = []
    try:
        values["hostname"] = socket.gethostname()
    except OSError as exc:
        errors.append(f"hostname: {exc}")
    try:
        values["platform"] = platform.platform()
        values["system"] = platform.system() or "unknown"
        values["release"] = platform.release() or "unknown"
        values["python_version"] = platform.python_version()
    except Exception as exc:  # platform providers can fail unexpectedly
        errors.append(f"platform: {exc}")
    item = result("available" if values else "error", values or None)
    if errors:
        item["errors"] = errors
        if not values:
            item["status"] = "error"
    return item


def _local_addresses(hostname: str) -> tuple[list[str], list[str]]:
    records = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    ipv4: list[str] = []
    ipv6: list[str] = []
    for record in records:
        address = record[4][0]
        if ":" in address:
            ipv6.append(address)
        else:
            ipv4.append(address)
    return unique(ipv4), unique(ipv6)


def _read_resolvers() -> dict[str, Any]:
    if os.name == "nt":
        return result("unavailable", error="Resolver configuration discovery is not implemented on Windows")
    path = Path("/etc/resolv.conf")
    try:
        nameservers = []
        for line in path.read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                nameservers.append(fields[1])
        if nameservers:
            return result("available", unique(nameservers))
        return result("unknown", error="No nameserver entries found in /etc/resolv.conf")
    except OSError as exc:
        return result("error", error=f"Could not read {path}: {exc}")


def _linux_default_gateway() -> dict[str, Any]:
    try:
        lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000":
                gateway = socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])
                return result("available", gateway)
        return result("unknown", error="No default IPv4 route found")
    except OSError as exc:
        return result("error", error=f"Could not read /proc/net/route: {exc}")
    except (ValueError, IndexError) as exc:
        return result("error", error=f"Could not parse /proc/net/route: {exc}")


def _command_output(command: list[str]) -> tuple[Optional[str], Optional[str]]:
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=5
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if completed.returncode != 0:
        return None, f"command exited with status {completed.returncode}"
    return completed.stdout, None


def _default_gateway() -> dict[str, Any]:
    if sys.platform.startswith("linux"):
        return _linux_default_gateway()
    if os.name == "nt":
        output, error = _command_output(["route", "print", "0.0.0.0"])
        if error:
            return result("unknown", error=error)
        for line in (output or "").splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[0] == "0.0.0.0" and fields[2] != "0.0.0.0":
                return result("available", fields[2])
        return result("unknown", error="No default route found")
    output, error = _command_output(["route", "-n"])
    if error:
        return result("unknown", error=error)
    for line in (output or "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "0.0.0.0":
            return result("available", fields[1])
    return result("unknown", error="No default route found")


def collect_network_info() -> dict[str, Any]:
    """Collect local addresses and best-effort platform network metadata."""
    errors: list[str] = []
    hostname = socket.gethostname()
    try:
        ipv4, ipv6 = _local_addresses(hostname)
        addresses = {
            "ipv4": result("available" if ipv4 else "unknown", ipv4),
            "ipv6": result("available" if ipv6 else "unknown", ipv6),
        }
    except socket.gaierror as exc:
        addresses = {
            "ipv4": result("error", error=f"Local hostname resolution failed: {exc}"),
            "ipv6": result("error", error=f"Local hostname resolution failed: {exc}"),
        }
        errors.append(str(exc))
    except OSError as exc:
        addresses = {"ipv4": result("error", error=str(exc)), "ipv6": result("error", error=str(exc))}
        errors.append(str(exc))
    try:
        interfaces = [name for _, name in socket.if_nameindex()]
        interface_result = result("available", interfaces)
    except (AttributeError, OSError) as exc:
        interface_result = result("unavailable", error=f"Interface enumeration unavailable: {exc}")
    data = {
        "addresses": addresses,
        "interfaces": interface_result,
        "default_gateway": _default_gateway(),
        "dns_resolvers": _read_resolvers(),
        "notes": [
            "Addresses are those returned for the local hostname, not a complete guarantee of every assigned address.",
            "Gateway and resolver discovery is platform-dependent and may be unavailable in containers or WSL.",
        ],
    }
    if errors:
        data["errors"] = errors
    return data


def resolve_hostname(hostname: str) -> dict[str, Any]:
    """Resolve one explicitly supplied hostname using socket facilities."""
    if not hostname or any(character.isspace() for character in hostname):
        return result("error", error="Hostname must be non-empty and contain no whitespace")
    try:
        records = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return result("error", error=f"DNS resolution failed: {exc}")
    except OSError as exc:
        return result("error", error=f"DNS lookup failed: {exc}")
    ipv4 = unique(record[4][0] for record in records if ":" not in record[4][0])
    ipv6 = unique(record[4][0] for record in records if ":" in record[4][0])
    addresses = {"ipv4": ipv4, "ipv6": ipv6}
    return result("available" if ipv4 or ipv6 else "unknown", addresses,
                  "Resolution returned no addresses" if not ipv4 and not ipv6 else None)


def test_tcp_connectivity(hostname: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """Test one explicitly requested TCP endpoint and close the socket reliably."""
    if not 1 <= port <= 65535:
        return result("error", error="Port must be between 1 and 65535")
    if not math.isfinite(timeout) or timeout <= 0:
        return result("error", error="Timeout must be finite and positive")
    try:
        addresses = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return result("error", error=f"DNS resolution failed: {exc}",)
    if not addresses:
        return result("error", error="DNS resolution returned no connection addresses")
    last_error: Optional[str] = None
    for family, socktype, proto, _, sockaddr in addresses:
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
            return result("available", {
                "hostname": hostname, "port": port, "reachable": True, "timeout_seconds": timeout
            })
        except socket.timeout:
            last_error = "Connection timed out"
        except ConnectionRefusedError:
            last_error = "Connection refused"
        except OSError as exc:
            last_error = f"Connection failed: {exc}"
    return result("error", {
        "hostname": hostname, "port": port, "reachable": False, "timeout_seconds": timeout
    }, last_error or "Connection failed")


def generate_summary() -> dict[str, Any]:
    """Collect the complete diagnostic data structure."""
    return {
        "system": collect_system_info(),
        "network": collect_network_info(),
    }


def _find_collection_errors(value: Any, path: str = "results") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        if value.get("error"):
            errors.append(f"{path}: {value['error']}")
        for key, child in value.items():
            if key != "error":
                errors.extend(_find_collection_errors(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_find_collection_errors(child, f"{path}[{index}]"))
    return errors


def build_report(kind: str, data: Any, target: Optional[str] = None) -> dict[str, Any]:
    report = {
        "schema_version": "1.0",
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "timestamp_utc": utc_timestamp(),
        "platform": {
            "system": platform.system() or "unknown",
            "platform": platform.platform() or "unknown",
            "python_version": platform.python_version(),
        },
        "operation": kind,
        "results": data,
        "collection_errors": _find_collection_errors(data),
        "disclaimer": "Network results depend on the current machine and are not security verdicts.",
    }
    if target is not None:
        report["target"] = target
    return report


def export_json_report(report: dict[str, Any], output: str) -> None:
    """Write a report atomically enough for a single local diagnostic file."""
    path = Path(output)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except OSError as exc:
        raise ValueError(f"Could not write report '{output}': {exc}") from exc


def _print_json_or_text(data: dict[str, Any], output: Optional[str]) -> None:
    if output:
        export_json_report(data, output)
        print(f"Report saved to {output}")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope.py",
        description="Read-only cross-platform local network information and diagnostics.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    summary = subparsers.add_parser("summary", help="collect local system and network information")
    summary.add_argument("--json", metavar="PATH", help="write the summary report as JSON")
    dns = subparsers.add_parser("dns", help="resolve one hostname")
    dns.add_argument("hostname")
    dns.add_argument("--json", metavar="PATH", help="write the DNS report as JSON")
    connectivity = subparsers.add_parser("connectivity", help="test one explicitly specified TCP endpoint")
    connectivity.add_argument("hostname")
    connectivity.add_argument("--port", type=int, required=True)
    connectivity.add_argument("--timeout", type=float, default=5.0)
    connectivity.add_argument("--json", metavar="PATH", help="write the connectivity report as JSON")
    full = subparsers.add_parser("full", help="collect a full local diagnostic report")
    full.add_argument("--json", metavar="PATH", help="write the full report as JSON")
    return parser


def main(argv: Optional[list[str]] = None, *,
         resolver: Callable[[str], dict[str, Any]] = resolve_hostname,
         connector: Callable[[str, int, float], dict[str, Any]] = test_tcp_connectivity) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "summary":
            report = build_report("summary", generate_summary())
            _print_json_or_text(report, args.json)
        elif args.command == "dns":
            report = build_report("dns", resolver(args.hostname), args.hostname)
            _print_json_or_text(report, args.json)
        elif args.command == "connectivity":
            report = build_report(
                "connectivity", connector(args.hostname, args.port, args.timeout),
                f"{args.hostname}:{args.port}",
            )
            _print_json_or_text(report, args.json)
        else:
            report = build_report("full", generate_summary())
            _print_json_or_text(report, args.json)
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())

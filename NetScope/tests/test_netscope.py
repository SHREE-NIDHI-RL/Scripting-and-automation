import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import netscope


class NetScopeTests(unittest.TestCase):
    def test_help(self):
        with self.assertRaises(SystemExit) as raised:
            netscope.main(["--help"])
        self.assertEqual(raised.exception.code, 0)

    def test_invalid_command(self):
        with self.assertRaises(SystemExit) as raised:
            netscope.main(["not-a-command"])
        self.assertNotEqual(raised.exception.code, 0)

    def test_invalid_port_and_timeout(self):
        self.assertEqual(netscope.test_tcp_connectivity("example.com", 0)["status"], "error")
        self.assertEqual(netscope.test_tcp_connectivity("example.com", 65536)["status"], "error")
        self.assertEqual(netscope.test_tcp_connectivity("example.com", 443, 0)["status"], "error")
        self.assertEqual(netscope.test_tcp_connectivity("example.com", 443, float("nan"))["status"], "error")

    @mock.patch("netscope.socket.getaddrinfo")
    def test_dns_success_deduplicates_addresses(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.0.2.1", 0)),
            (2, 1, 6, "", ("192.0.2.1", 0)),
            (10, 1, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]
        value = netscope.resolve_hostname("example.com")
        self.assertEqual(value["status"], "available")
        self.assertEqual(value["value"]["ipv4"], ["192.0.2.1"])
        self.assertEqual(value["value"]["ipv6"], ["2001:db8::1"])

    @mock.patch("netscope.socket.getaddrinfo", side_effect=netscope.socket.gaierror("not found"))
    def test_dns_failure(self, _getaddrinfo):
        value = netscope.resolve_hostname("invalid.example")
        self.assertEqual(value["status"], "error")
        self.assertIn("DNS resolution failed", value["error"])

    @mock.patch("netscope.socket.socket")
    @mock.patch("netscope.socket.getaddrinfo")
    def test_tcp_success(self, getaddrinfo, socket_factory):
        getaddrinfo.return_value = [(2, 1, 6, "", ("192.0.2.1", 443))]
        value = netscope.test_tcp_connectivity("example.com", 443, 2)
        self.assertEqual(value["status"], "available")
        socket_factory.return_value.__enter__.return_value.connect.assert_called_once()

    @mock.patch("netscope.socket.socket")
    @mock.patch("netscope.socket.getaddrinfo")
    def test_tcp_refused(self, getaddrinfo, socket_factory):
        getaddrinfo.return_value = [(2, 1, 6, "", ("192.0.2.1", 443))]
        socket_factory.return_value.__enter__.return_value.connect.side_effect = ConnectionRefusedError()
        value = netscope.test_tcp_connectivity("example.com", 443)
        self.assertEqual(value["status"], "error")
        self.assertEqual(value["error"], "Connection refused")

    @mock.patch("netscope.platform.platform", return_value="")
    @mock.patch("netscope.platform.system", return_value="")
    def test_missing_platform_information(self, _system, _platform):
        value = netscope.collect_system_info()
        self.assertEqual(value["status"], "available")
        self.assertEqual(value["value"]["system"], "unknown")

    @mock.patch("netscope.socket.if_nameindex", side_effect=OSError("not permitted"))
    @mock.patch("netscope._default_gateway", return_value=netscope.result("unknown"))
    @mock.patch("netscope._read_resolvers", return_value=netscope.result("unknown"))
    def test_optional_collection_failure(self, _resolvers, _gateway, _interfaces):
        value = netscope.collect_network_info()
        self.assertEqual(value["interfaces"]["status"], "unavailable")

    @mock.patch("netscope.subprocess.run", side_effect=OSError("command unavailable"))
    def test_optional_system_command_failure(self, _run):
        value = netscope._command_output(["route", "print"])
        self.assertIsNone(value[0])
        self.assertIn("command unavailable", value[1])

    def test_json_schema_and_serialization(self):
        report = netscope.build_report("dns", netscope.result("available", {"ipv4": ["192.0.2.1"]}), "example.com")
        encoded = json.dumps(report)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["tool"]["name"], "NetScope")
        self.assertEqual(decoded["operation"], "dns")
        error_report = netscope.build_report("summary", {"network": netscope.result("error", error="not available")})
        self.assertEqual(len(error_report["collection_errors"]), 1)

    def test_report_write_failure(self):
        report = netscope.build_report("summary", {})
        with tempfile.TemporaryDirectory() as directory:
            parent_file = Path(directory) / "parent-file"
            parent_file.write_text("not a directory", encoding="utf-8")
            target = parent_file / "report.json"
            with self.assertRaises(ValueError):
                netscope.export_json_report(report, str(target))

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with mock.patch("netscope.generate_summary", return_value={"system": {}}):
                self.assertEqual(netscope.main(["summary", "--json", str(output)]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["operation"], "summary")

    def test_cli_dns_uses_injected_resolver(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                netscope.main(["dns", "example.com"], resolver=lambda _: netscope.result("available", {"ipv4": ["192.0.2.1"], "ipv6": []})),
                0,
            )
        self.assertIn('"example.com"', output.getvalue())


if __name__ == "__main__":
    unittest.main()

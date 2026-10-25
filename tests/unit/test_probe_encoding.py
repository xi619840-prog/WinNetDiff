import base64
import codecs
import json
import socket
import ssl
import subprocess
import threading
import unittest
from unittest.mock import MagicMock, patch

import windows_net_diffdiag as app


ADDR4 = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", 443))
ADDR4_B = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.11", 443))


class EncodingTests(unittest.TestCase):
    def test_cp936_chinese_command_evidence(self):
        text = '"閃連 VPN","正在執行","C:\\使用者\\測試\\驅動.sys"'
        with patch.object(app, "_native_codepages", return_value=["cp936"]):
            decoded, encoding, error = app.decode_output(text.encode("cp936"))
        self.assertEqual(text, decoded)
        self.assertEqual("cp936", encoding)
        self.assertIn("utf-8", error)

    def test_bom_priority(self):
        text = '{"服務":"深信服"}'
        self.assertEqual(text, app.decode_output(codecs.BOM_UTF8 + text.encode("utf-8"), "cp936")[0])
        self.assertEqual(text, app.decode_output(text.encode("utf-16"), "cp936")[0])

    def test_ps_utf8_json(self):
        text = '[{"Name":"中文服務","Path":"C:\\\\軟體\\\\測試.exe"}]'
        self.assertEqual(text, app.decode_output(text.encode("utf-8"), "powershell")[0])

    def test_undecodable_forced_utf8_retains_raw(self):
        process = subprocess.CompletedProcess(["route"], 0, b"\xff\x80", b"")
        # An allowlisted system tool name: bare unknown names are refused on Windows.
        with patch.object(app.subprocess, "run", return_value=process):
            res = app.run_command(["route", "print"], encoding_hint="powershell")
        self.assertFalse(res["ok"])
        self.assertEqual(b"\xff\x80", base64.b64decode(res["stdout_raw_base64"]))
        self.assertNotIn("\ufffd", res["stdout"])
        self.assertTrue(res["decode_errors"])

    def test_subprocess_is_bytes_without_shell(self):
        with patch.object(app.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"ok", b"")) as run:
            app.run_command(["route", "print", "-4"])
        self.assertFalse(run.call_args.kwargs["text"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertNotIn("errors", run.call_args.kwargs)

    def test_native_commands_codepage_compatibility(self):
        for command in ("driverquery", "netstat", "tasklist", "route", "netsh"):
            with self.subTest(command=command), patch.object(app, "_native_codepages", return_value=["cp936"]), patch.object(
                    app.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "中文網路服務".encode("cp936"), b"")):
                self.assertEqual("中文網路服務", app.run_command([command])["stdout"])

    def test_timeout_preserves_partial_output(self):
        with patch.object(app.subprocess, "run", side_effect=subprocess.TimeoutExpired(["route"], 1, b"partial", b"stderr")):
            res = app.run_command(["route", "print"], timeout=1)
        self.assertFalse(res["ok"])
        self.assertTrue(res["timed_out"])
        self.assertEqual("partial", res["stdout"])
        self.assertIn("stderr", res["stderr"])

    def test_powershell_encoded_command_and_explicit_output(self):
        with patch.object(app, "run_command", return_value={"ok": True}) as run:
            app.powershell("[pscustomobject]@{Name='中文服務'} | ConvertTo-Json")
        args = run.call_args.args[0]
        self.assertIn("-EncodedCommand", args)
        decoded = base64.b64decode(args[-1]).decode("utf-16-le")
        self.assertIn("中文服務", decoded)
        self.assertIn("UTF8Encoding", decoded)
        self.assertIn("$ErrorActionPreference='Stop'", decoded)

    def test_ps_json_empty_or_malformed_is_not_empty_success(self):
        for output in ("", "not json", "[1,2]"):
            with self.subTest(output=output), patch.object(app, "powershell", return_value={"ok": True, "stdout": output}):
                rows, error = app.ps_json("test")
            self.assertEqual([], rows)
            self.assertTrue(error)

    def test_ps_permission_error_preserved(self):
        with patch.object(app, "powershell", return_value={"ok": False, "stderr": "Access denied: 權限不足"}):
            rows, error = app.ps_json("Get-CimInstance root/SecurityCenter2")
        self.assertFalse(rows)
        self.assertIn("權限不足", error)


class ProbeTests(unittest.TestCase):
    def run_probe(self, tcp_error=None, tls_error=None, chunks=None, http_error=None):
        raw = MagicMock()
        raw.connect.side_effect = tcp_error
        secure = MagicMock()
        secure.do_handshake.side_effect = tls_error
        secure.version.return_value = "TLSv1.3"
        secure.recv.side_effect = http_error or (chunks if chunks is not None else [b"HTTP/1.1 200 OK\r\n"])
        context = MagicMock()
        context.wrap_socket.return_value = secure
        with patch.object(app.socket, "socket", return_value=raw), patch.object(app.ssl, "create_default_context", return_value=context):
            result = app.probe_endpoint("example.com", socket.AF_INET, ADDR4, 1.0)
        self.assertTrue(raw.close.called)
        if not tcp_error:
            self.assertTrue(secure.close.called)
            context.wrap_socket.assert_called_once_with(raw, server_hostname="example.com", do_handshake_on_connect=False)
        return result, raw, secure

    def test_tcp_timeout_is_not_tls_failure(self):
        result, _, secure = self.run_probe(tcp_error=TimeoutError("connect timeout"))
        self.assertEqual("tcp_timeout", result.stage)
        self.assertEqual("tcp", result.timeout_stage)
        self.assertIsNotNone(result.tcp_ms)
        self.assertIsNone(result.tls_ms)
        self.assertFalse(secure.do_handshake.called)

    def test_tcp_success_tls_timeout(self):
        result, raw, secure = self.run_probe(tls_error=TimeoutError("TLS timeout"))
        self.assertEqual("tls_timeout", result.stage)
        self.assertEqual("tls", result.timeout_stage)
        self.assertIsNotNone(result.tcp_ms)
        self.assertIsNotNone(result.tls_ms)
        self.assertFalse(secure.sendall.called)

    def test_tls_success_http_timeout(self):
        result, _, _ = self.run_probe(http_error=TimeoutError("HTTP timeout"))
        self.assertEqual("http_timeout", result.stage)
        self.assertEqual("http", result.timeout_stage)
        self.assertIsNotNone(result.tls_ms)
        self.assertIsNotNone(result.http_ms)

    def test_certificate_validation_failure(self):
        result, _, _ = self.run_probe(tls_error=ssl.SSLCertVerificationError(1, "certificate verify failed"))
        self.assertEqual("tls_cert_error", result.stage)
        self.assertEqual("SSLCertVerificationError", result.error_type)

    def test_fragmented_http_status_line(self):
        result, raw, secure = self.run_probe(chunks=[b"HTTP/1.", b"1 403 For", b"bidden\r\n"])
        self.assertEqual("http_ok", result.stage)
        self.assertEqual(403, result.http_status)
        self.assertEqual(1, raw.connect.call_count)
        self.assertEqual(1, secure.do_handshake.call_count)
        self.assertEqual(3, secure.recv.call_count)

    def test_non_http_response_is_not_success(self):
        result, _, _ = self.run_probe(chunks=[b"not HTTP\r\n"])
        self.assertEqual("http_protocol_error", result.stage)
        self.assertIsNone(result.http_status)

    def test_empty_http(self):
        result, _, _ = self.run_probe(chunks=[b""])
        self.assertEqual("http_empty", result.stage)

    def test_cancelled_probe_does_not_create_socket(self):
        cancel = threading.Event()
        cancel.set()
        with patch.object(app.socket, "socket") as factory:
            result = app.probe_endpoint("example.com", socket.AF_INET, ADDR4, 0, cancel=cancel)
        self.assertEqual("cancelled", result.stage)
        self.assertFalse(factory.called)

    def test_socket_creation_error_is_recorded(self):
        with patch.object(app.socket, "socket", side_effect=OSError("resource exhausted")):
            result = app.probe_endpoint("example.com", socket.AF_INET, ADDR4, 0)
        self.assertEqual("tcp_error", result.stage)

    def test_rotation_retains_all_attempts_and_intermittency(self):
        bad = app.Probe("example.com", "IPv4", ip="203.0.113.10", stage="tls_timeout", tcp_ms=1, tls_ms=6000)
        good = app.Probe("example.com", "IPv4", ip="203.0.113.11", stage="http_ok", tcp_ms=1, tls_ms=2, http_ms=3)
        with patch.object(app, "timeout_dns", return_value=([ADDR4, ADDR4_B], "", 1.0)), patch.object(
                app, "probe_endpoint", side_effect=[bad, good]) as endpoint:
            result = app.probe_host_family("example.com", socket.AF_INET, retries=2, retry_mode='rotate')
        self.assertEqual("http_ok", result.stage)
        self.assertTrue(result.intermittent)
        self.assertEqual(["tls_timeout", "http_ok"], [x["stage"] for x in result.attempts])
        self.assertEqual(ADDR4_B, endpoint.call_args_list[1].args[2])

    def test_dns_timeout_has_separate_stage(self):
        with patch.object(app, "timeout_dns", return_value=([], "DNSTimeout: timed out", 6000)):
            result = app.probe_host_family("example.com", socket.AF_INET)
        self.assertEqual("dns_timeout", result.stage)
        self.assertEqual("dns", result.timeout_stage)

    def test_dns_cancelled(self):
        cancel = threading.Event()
        cancel.set()
        with patch.object(app.socket, "getaddrinfo") as resolve:
            addresses, error, _ = app.timeout_dns("example.com", socket.AF_INET, cancel=cancel)
        self.assertFalse(addresses)
        self.assertIn("Cancelled", error)
        self.assertFalse(resolve.called)

    def test_dns_thread_start_failure_releases_slot(self):
        slots = threading.BoundedSemaphore(1)
        thread = MagicMock()
        thread.start.side_effect = RuntimeError('cannot start new thread')
        with patch.object(app, '_DNS_SLOTS', slots), patch.object(app.threading, 'Thread', return_value=thread):
            addresses, error, _ = app.timeout_dns('example.com', socket.AF_INET)
        self.assertEqual([], addresses)
        self.assertIn('DNSWorkerError', error)
        self.assertTrue(slots.acquire(blocking=False))
        slots.release()

    def test_overall_budget_prevents_starting_expired_tcp(self):
        ticks = iter([0.0, 0.1, 0.2, 0.3])
        with patch.object(app.time, 'perf_counter', side_effect=lambda: next(ticks)), patch.object(app.socket, 'socket') as factory:
            result = app.probe_endpoint('example.com', socket.AF_INET, ADDR4, 0, overall_timeout=0.01)
        self.assertEqual('overall_timeout', result.stage)
        self.assertEqual('overall', result.timeout_stage)
        self.assertFalse(factory.called)


if __name__ == "__main__":
    unittest.main()

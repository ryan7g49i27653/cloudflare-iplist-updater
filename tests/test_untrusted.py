"""Adversarial input tests: everything from the network is rejected unless it is
exactly the expected shape, and rejected input never appears in error text."""

import http.server
import ipaddress
import logging
import threading
import unittest
from unittest import mock

from cf_iplist_updater import app, cloudflare, detect_fortigate, detect_web, httpclient, reconcile
from cf_iplist_updater.config import Cloudflare
from cf_iplist_updater.untrusted import (UntrustedDataError, describe, ip_address, ip_network,
                                         opaque_id, text_body)

A = ipaddress.ip_address
SENTINEL = "PWN3D"

HOSTILE_ADDRESSES = [
    "2001:db8::1%eth0",                    # IPv6 scope id (accepted by ipaddress)
    f"2001:db8::1%\x1b[31m{SENTINEL}",     # scope id carrying a terminal escape
    "::ffff:192.0.2.1",                    # IPv4-mapped
    "2001:db8::192.0.2.1",                 # embedded dotted quad
    "192.000.2.1", " 192.0.2.1", "192.0.2.1\n", "192.0.2.1\x00",
    "١٩٢.0.2.1",            # non-ASCII digits
    "192.0.2.1; rm -rf /", f"<script>{SENTINEL}</script>", "${jndi:ldap://x}",
    "1" * 5000, "", "0x7f.1", "192.0.2", "2001:db8:::1",
]


class StrictParserTests(unittest.TestCase):
    def test_hostile_addresses_rejected(self):
        for value in HOSTILE_ADDRESSES:
            with self.subTest(value=describe(value, 40)):
                with self.assertRaises(UntrustedDataError) as cm:
                    ip_address(value)
                self.assertNotIn(SENTINEL, str(cm.exception))
                if len(value) > 3:
                    self.assertNotIn(value, str(cm.exception))

    def test_non_strings_rejected(self):
        for value in (3232235777, 3.14, None, True, ["192.0.2.1"], {"ip": "192.0.2.1"}, b"192.0.2.1"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(UntrustedDataError):
                    ip_address(value)
                with self.assertRaises(UntrustedDataError):
                    ip_network(value)

    def test_valid_addresses_canonicalized(self):
        self.assertEqual(str(ip_address("2001:DB8:0::1")), "2001:db8::1")
        self.assertEqual(ip_address("192.0.2.1", 4), A("192.0.2.1"))
        with self.assertRaises(UntrustedDataError):
            ip_address("192.0.2.1", 6)

    def test_networks(self):
        self.assertEqual(str(ip_network("2001:db8:1f::5/64")), "2001:db8:1f::/64")
        self.assertEqual(str(ip_network("192.0.2.1")), "192.0.2.1/32")
        for value in ("2001:db8::/64%x", "2001:db8::1%x/64", "2001:db8::/", "2001:db8::/-1",
                      "2001:db8::/999", "2001:db8::/64/64", "2001:db8::/ 64", "192.0.2.0/24\n"):
            with self.subTest(value=describe(value)):
                with self.assertRaises(UntrustedDataError):
                    ip_network(value)

    def test_opaque_ids(self):
        self.assertEqual(opaque_id("0123456789abcdef0123456789abcdef"), "0123456789abcdef0123456789abcdef")
        for value in ("../../user", "a/b", "a?b", "a#b", "a b", "a%2f", "", "x" * 65, None, 5):
            with self.subTest(value=repr(value)):
                with self.assertRaises(UntrustedDataError):
                    opaque_id(value)

    def test_text_body(self):
        self.assertEqual(text_body(b"192.0.2.1\r\n", 100), "192.0.2.1\r\n")
        for body in (b"\xef\xbb\xbf192.0.2.1", b"192.0.2.1\x1b[0m", b"192.0.2.1\x00",
                     "192.0.2.1‮".encode(), b"x" * 101):
            with self.subTest(body=body[:20]):
                with self.assertRaises(UntrustedDataError):
                    text_body(body, 100)

    def test_describe_escapes(self):
        self.assertEqual(describe("a\x1b[31mb\nc‮d"), "a\\x1b[31mb\\x0ac\\u202ed")
        self.assertEqual(describe("x" * 100, 10), "x" * 10 + "...")
        self.assertTrue(all(" " <= c <= "~" for c in describe("\U0001f600\x00\x7f")))


@mock.patch.object(detect_web, "is_public", lambda a: True)
class EchoAdversarialTests(unittest.TestCase):
    def test_hostile_bodies_rejected(self):
        bodies = [
            b"<html><body>192.0.2.1</body></html>",
            b'{"ip": "192.0.2.1"}',
            b"192.0.2.1\n198.51.100.1\n",
            b"fl=1\nip=192.0.2.1\nip=198.51.100.1\n",
            b"ip=192.0.2.1; curl evil|sh\n",
            b"MTkyLjAuMi4x",                       # base64 of an address
            b"192.0.2.1\x1b]0;" + SENTINEL.encode() + b"\x07",
            b"2001:db8::1%25eth0",
            b"",
            b"192.0.2.1" + b" " * 2000,
        ]
        for body in bodies:
            with self.subTest(body=body[:30]):
                with self.assertRaises(UntrustedDataError) as cm:
                    detect_web.parse_echo(body)
                self.assertNotIn(SENTINEL, str(cm.exception))

    def test_trace_and_plain_ok(self):
        self.assertEqual(detect_web.parse_echo(b"  192.0.2.1  \r\n"), A("192.0.2.1"))
        trace = b"fl=1\nh=one.one.one.one\nip=192.0.2.1\nuag=cf-iplist-updater/1.0\n"
        self.assertEqual(detect_web.parse_echo(trace), A("192.0.2.1"))

    def test_fetch_requires_200_and_text_plain(self):
        cases = [httpclient.Response(200, b"192.0.2.1", "text/html"),
                 httpclient.Response(200, b"192.0.2.1", "application/json"),
                 httpclient.Response(203, b"192.0.2.1", "text/plain")]
        for resp in cases:
            with self.subTest(resp=resp):
                with mock.patch.object(httpclient, "request", return_value=resp):
                    with self.assertRaises(UntrustedDataError):
                        detect_web.fetch("https://echo.example", 1)
        ok = httpclient.Response(200, b"192.0.2.1\n", "text/plain; charset=utf-8")
        with mock.patch.object(httpclient, "request", return_value=ok):
            self.assertEqual(detect_web.fetch("https://echo.example", 1), A("192.0.2.1"))

    def test_hostile_echo_does_not_count_toward_quorum(self):
        answers = [UntrustedDataError("bad"), A("192.0.2.1"), UntrustedDataError("bad")]
        with mock.patch.object(detect_web, "fetch", side_effect=answers):
            self.assertIsNone(detect_web.detect(4, ["a", "b", "c"], 2, 1))


class FortiGateAdversarialTests(unittest.TestCase):
    def test_hostile_wan_ip_rejected(self):
        for ip in (3232235777, "192.0.2.1%x", "192.0.2.1 ", ["192.0.2.1"], "::ffff:192.0.2.1"):
            payload = {"status": "success", "results": {"wan1": {"ip": ip}}}
            with self.subTest(ip=repr(ip)):
                with self.assertRaises(detect_fortigate.FortiGateError):
                    detect_fortigate.parse_wan_ipv4(payload, "wan1")

    def test_hostile_routes_skipped(self):
        routes = {"status": "success", "results": [
            {"interface": "LAN", "type": "connect", "ip_mask": "2001:db8:1f::/64%\x1b[31m"},
            {"interface": "LAN", "type": "connect", "ip_mask": 42},
            {"interface": "LAN", "type": "connect", "ip_mask": "2001:db8::1%eth0/64"},
            "not-a-dict",
            {"interface": "LAN", "type": "connect", "ip_mask": "2001:db8:1f::/64"},
        ]}
        with mock.patch.object(detect_fortigate, "is_public", lambda a: True):
            nets = detect_fortigate.parse_delegated_prefixes(routes, "wan1")
        self.assertEqual([str(n) for n in nets], ["2001:db8:1f::/64"])

    def test_unexpected_shapes(self):
        for payload in ({"status": "success", "results": "x"}, {"status": "weird"}, {}):
            with self.subTest(payload=payload):
                with self.assertRaises(detect_fortigate.FortiGateError):
                    detect_fortigate.parse_delegated_prefixes(payload, "wan1")


def ok(result, **extra):
    return {"success": True, "errors": [], "result": result, **extra}


class CloudflareAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.cf = cloudflare.CloudflareClient(
            Cloudflare(api_token="t", account_id="acct", list_id="lst"), poll_interval=0)

    def test_operation_id_path_injection_rejected(self):
        for op in ("../../../user/tokens", "op?x=1", None, 5):
            with self.subTest(op=op):
                with mock.patch.object(httpclient, "request_json", side_effect=[ok({"operation_id": op})]) as rj:
                    with self.assertRaisesRegex(cloudflare.CloudflareError, "invalid bulk operation id"):
                        self.cf.add_items([{"ip": "192.0.2.1", "comment": "x"}])
                self.assertEqual(rj.call_count, 1)  # never polled the injected path

    def test_item_id_injection_rejected_before_request(self):
        with mock.patch.object(httpclient, "request_json") as rj:
            with self.assertRaises(UntrustedDataError):
                self.cf.delete_items(["ok-id", "../x"])
        rj.assert_not_called()

    def test_error_text_escaped(self):
        payload = {"success": False, "errors": [{"code": "7\n", "message": f"bad\x1b[2J{SENTINEL}\nline"}]}
        with mock.patch.object(httpclient, "request_json", return_value=payload):
            with self.assertRaises(cloudflare.CloudflareError) as cm:
                self.cf.get_list()
        msg = str(cm.exception)
        self.assertNotIn("\x1b", msg)
        self.assertNotIn("\n", msg)
        self.assertIn("[?]", msg)

    def test_success_must_be_true(self):
        for value in ("true", 1, None):
            with mock.patch.object(httpclient, "request_json", return_value={"success": value, "result": {}}):
                with self.assertRaises(cloudflare.CloudflareError):
                    self.cf.get_list()

    def test_endless_pagination_stopped(self):
        page = ok([{"id": "1"}], result_info={"cursors": {"after": "same"}})
        with mock.patch.object(httpclient, "request_json", return_value=page):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "pages"):
                self.cf.list_items()

    def test_reconcile_ignores_hostile_items(self):
        marker = "managed-by:test-marker"
        items = [{"id": "a", "ip": "2001:db8::1%\x1b[31m", "comment": marker},
                 {"id": "b", "ip": "192.0.2.1", "comment": [marker]},
                 {"id": "c", "ip": 3232235777, "comment": marker}]
        p = reconcile.plan({4: [ipaddress.ip_network("192.0.2.9/32")], 6: None}, items, marker)
        self.assertEqual(p.to_remove, [])
        self.assertEqual([str(n) for n in p.to_add], ["192.0.2.9/32"])


class _Handler(http.server.BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/steal")
            self.end_headers()
        else:
            _Handler.seen.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 100)


class HTTPClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_redirect_refused_and_token_not_forwarded(self):
        _Handler.seen.clear()
        import urllib.error
        import urllib.request
        req = urllib.request.Request(f"{self.base}/redirect", headers={"Authorization": "Bearer SECRET"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            httpclient._opener(None).open(req, timeout=5)
        self.assertEqual(cm.exception.code, 302)
        self.assertEqual(_Handler.seen, [])

    def test_plain_http_refused(self):
        with self.assertRaisesRegex(httpclient.HTTPError, "only https"):
            httpclient.request("GET", f"{self.base}/x")

    def test_response_size_capped(self):
        import urllib.request
        with httpclient._opener(None).open(f"{self.base}/big", timeout=5) as resp:
            with self.assertRaisesRegex(httpclient.HTTPError, "larger than 50 bytes"):
                httpclient._read_capped(resp, 50, "test")

    def test_tls_minimum(self):
        import ssl
        self.assertEqual(httpclient.make_ssl_context().minimum_version, ssl.TLSVersion.TLSv1_2)


class LogEscapeTests(unittest.TestCase):
    def test_filter_escapes_control_characters(self):
        record = logging.LogRecord("x", logging.WARNING, __file__, 1, "echo %s: %s",
                                   ("https://e.example", "bad\nFAKE LOG LINE\x1b[2J"), None)
        app.EscapeFilter().filter(record)
        msg = record.getMessage()
        self.assertNotIn("\n", msg)
        self.assertNotIn("\x1b", msg)
        self.assertIn("\\x0aFAKE LOG LINE\\x1b[2J", msg)


if __name__ == "__main__":
    unittest.main()

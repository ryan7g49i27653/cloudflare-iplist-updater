import ipaddress
import unittest
from unittest import mock

from cf_iplist_updater import detect_fortigate as fgmod
from cf_iplist_updater import detect_web, httpclient

A = ipaddress.ip_address


def always_public(addr):
    return True


@mock.patch.object(detect_web, "is_public", always_public)
class EchoTests(unittest.TestCase):
    def test_parse_plain_and_trace(self):
        self.assertEqual(detect_web.parse_echo(b"192.0.2.10\n"), A("192.0.2.10"))
        trace = b"fl=1\nh=1.1.1.1\nip=2001:db8::5\nts=1\n"
        self.assertEqual(detect_web.parse_echo(trace), A("2001:db8::5"))

    def test_quorum_reached(self):
        with mock.patch.object(detect_web, "fetch", side_effect=[A("192.0.2.10")] * 2) as f:
            self.assertEqual(detect_web.detect(4, ["u1", "u2", "u3"], 2, 1), A("192.0.2.10"))
            self.assertEqual(f.call_count, 2)  # stops once quorum is met

    def test_disagreement_returns_none(self):
        answers = [A("192.0.2.10"), A("192.0.2.11"), A("192.0.2.12")]
        with mock.patch.object(detect_web, "fetch", side_effect=answers):
            self.assertIsNone(detect_web.detect(4, ["u1", "u2", "u3"], 2, 1))

    def test_errors_and_wrong_family_skipped(self):
        answers = [httpclient.HTTPError("boom"), A("2001:db8::1"), A("192.0.2.10"), A("192.0.2.10")]
        with mock.patch.object(detect_web, "fetch", side_effect=answers):
            self.assertEqual(detect_web.detect(4, ["a", "b", "c", "d"], 2, 1), A("192.0.2.10"))


class NonPublicTests(unittest.TestCase):
    def test_private_and_cgnat_rejected(self):
        answers = [A("10.0.0.1"), A("100.64.0.1")]
        with mock.patch.object(detect_web, "fetch", side_effect=answers):
            self.assertIsNone(detect_web.detect(4, ["a", "b"], 1, 1))


class FortiGateParseTests(unittest.TestCase):
    def test_monitor_dict_shape(self):
        payload = {"status": "success",
                   "results": {"wan1": {"name": "wan1", "ip": "192.0.2.10", "mask": 24}}}
        self.assertEqual(fgmod.parse_wan_ipv4(payload, "wan1"), A("192.0.2.10"))

    def test_monitor_list_shape(self):
        payload = {"status": "success", "results": [{"name": "wan1", "ip": "192.0.2.10"}]}
        self.assertEqual(fgmod.parse_wan_ipv4(payload, "wan1"), A("192.0.2.10"))

    def test_monitor_no_address(self):
        payload = {"status": "success", "results": {"wan1": {"name": "wan1", "ip": "0.0.0.0"}}}
        with self.assertRaises(fgmod.FortiGateError):
            fgmod.parse_wan_ipv4(payload, "wan1")

    def test_monitor_missing_interface(self):
        with self.assertRaises(fgmod.FortiGateError):
            fgmod.parse_wan_ipv4({"status": "success", "results": {}}, "wan1")

    def test_monitor_api_error(self):
        payload = {"http_method": "GET", "status": "error", "http_status": 403}
        with self.assertRaisesRegex(fgmod.FortiGateError, "403"):
            fgmod.parse_wan_ipv4(payload, "wan1")

    # Shape of GET /api/v2/monitor/router/ipv6 on FortiOS 7.6.8.
    ROUTES = {"status": "success", "results": [
        {"interface": "wan1", "ip_mask": "::/0", "type": "static"},
        {"interface": "root", "ip_mask": "::1/128", "type": "connect"},
        {"interface": "wan1", "ip_mask": "2001:db8:1e::48/128", "type": "connect"},
        {"interface": "LAN", "ip_mask": "2001:db8:1f::/64", "type": "connect"},
        {"interface": "LAN", "ip_mask": "fe80::/64", "type": "connect"},
        {"interface": "guest", "ip_mask": "fd00:1::/64", "type": "connect"},
        {"interface": "iot", "ip_mask": "2001:db8:1f:1::/64", "type": "connect"},
        {"interface": "LAN", "ip_mask": "2001:db8:1f:9::/64", "type": "static"},
    ]}

    def test_delegated_prefixes(self):
        # Documentation prefixes stand in for global ones.
        with mock.patch.object(fgmod, "is_public", lambda a: str(a).startswith("2001:db8")):
            nets = fgmod.parse_delegated_prefixes(self.ROUTES, "wan1")
            self.assertEqual(nets, [ipaddress.ip_network("2001:db8:1f::/64"),
                                    ipaddress.ip_network("2001:db8:1f:1::/64")])
            nets = fgmod.parse_delegated_prefixes(self.ROUTES, "wan1", ["LAN"])
            self.assertEqual(nets, [ipaddress.ip_network("2001:db8:1f::/64")])

    def test_monitor_request_includes_aggregate_and_vlan(self):
        from cf_iplist_updater.config import FortiGate
        client = fgmod.FortiGateClient(FortiGate(host="fortigate.example.internal",
                                                 api_token="t", wan_interface="wan1"))
        payload = {"status": "success", "results": {"wan1": {"name": "wan1", "ip": "192.0.2.10"}}}
        with mock.patch.object(httpclient, "request_json", return_value=payload) as rj:
            self.assertEqual(client.wan_ipv4(), A("192.0.2.10"))
        url = rj.call_args.args[1]
        self.assertIn("interface_name=wan1", url)
        self.assertIn("include_aggregate=true", url)
        self.assertIn("include_vlan=true", url)

    def test_delegated_prefixes_api_error(self):
        with self.assertRaises(fgmod.FortiGateError):
            fgmod.parse_delegated_prefixes({"status": "error", "http_status": 403}, "wan1")


if __name__ == "__main__":
    unittest.main()

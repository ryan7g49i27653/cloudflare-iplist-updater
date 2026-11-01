import ipaddress
import json
import tempfile
import unittest
from unittest import mock

from cf_iplist_updater import app, detect_web
from cf_iplist_updater.detect_fortigate import FortiGateError

from .helpers import MARKER, item, make_config

A = ipaddress.ip_address
N = ipaddress.ip_network


class FakeFortiGate:
    def __init__(self, ipv4="192.0.2.10", prefixes=("2001:db8:1f::/60",)):
        self.ipv4, self.prefixes = ipv4, prefixes

    def wan_ipv4(self):
        if isinstance(self.ipv4, Exception):
            raise self.ipv4
        return A(self.ipv4)

    def delegated_prefixes(self):
        if isinstance(self.prefixes, Exception):
            raise self.prefixes
        return [N(p) for p in self.prefixes]


class FakeCloudflare:
    def __init__(self, items):
        self.items = list(items)
        self.added, self.deleted = [], []

    def list_items(self):
        return list(self.items)

    def add_items(self, items):
        self.added.extend(items)

    def delete_items(self, ids):
        self.deleted.extend(ids)


V6_DOWN = FakeFortiGate(prefixes=FortiGateError("down"))


def fake_echo(v4="192.0.2.10", v6="2001:db8:1f:a::5"):
    def detect(version, services, quorum, timeout):
        value = v4 if version == 4 else v6
        return A(value) if value else None
    return detect


@mock.patch.object(app, "is_public", lambda a: True)
class DetectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_config(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def detect(self, fg, st=None, echo=None):
        with mock.patch.object(detect_web, "detect", echo or fake_echo()) as e:
            return app.detect(self.cfg, st or {}, fg)

    def test_fortigate_ipv4_and_prefixes(self):
        fg = FakeFortiGate(prefixes=("2001:db8:1f::/64", "2001:db8:1e::/64"))
        det = self.detect(fg, echo=fake_echo(v4=None, v6=None))  # echo unused
        self.assertEqual(det.desired, {4: [N("192.0.2.10/32")],
                                       6: [N("2001:db8:1f::/64"), N("2001:db8:1e::/64")]})
        self.assertEqual((det.errors, det.warnings), ([], []))

    def test_unacceptable_prefix_skipped(self):
        fg = FakeFortiGate(prefixes=("2001:db8:1f::/64", "2001:db8:1f:a::/80"))
        det = self.detect(fg)
        self.assertEqual(det.desired[6], [N("2001:db8:1f::/64")])
        self.assertEqual(len(det.warnings), 1)

    def test_fortigate_down_echo_within_last_known(self):
        fg = FakeFortiGate(ipv4=FortiGateError("timeout"), prefixes=FortiGateError("timeout"))
        st = {"last_known": {"6": ["2001:db8:1f::/60", "2001:db8:99::/64"]}}
        det = self.detect(fg, st, fake_echo(v4="192.0.2.77"))
        self.assertEqual(det.desired, {4: [N("192.0.2.77/32")],
                                       6: [N("2001:db8:1f::/60"), N("2001:db8:99::/64")]})
        self.assertEqual(det.errors, [])
        self.assertEqual(len(det.warnings), 2)

    def test_fortigate_down_new_prefix_uses_last_length(self):
        fg = FakeFortiGate(prefixes=FortiGateError("timeout"))
        st = {"last_known": {"6": ["2001:db8:aa::/56"]}}
        det = self.detect(fg, st)
        self.assertEqual(det.desired[6], [N("2001:db8:1f::/56")])

    def test_fallback_length_from_config(self):
        self.cfg.ipv6.fallback_prefix_length = 64
        det = self.detect(FakeFortiGate(prefixes=FortiGateError("timeout")))
        self.assertEqual(det.desired[6], [N("2001:db8:1f:a::/64")])

    def test_no_length_anywhere_is_error(self):
        det = self.detect(FakeFortiGate(prefixes=FortiGateError("timeout")))
        self.assertIsNone(det.desired[6])
        self.assertTrue(det.errors)

    def test_no_prefixes_on_fortigate_falls_back(self):
        st = {"last_known": {"6": ["2001:db8:1f::/60"]}}
        det = self.detect(FakeFortiGate(prefixes=()), st)
        self.assertEqual(det.desired[6], [N("2001:db8:1f::/60")])
        self.assertEqual(len(det.warnings), 1)


@mock.patch.object(app, "is_public", lambda a: True)
class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_config(self.tmp.name)
        self.cfg.general.state_dir.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_app(self, items, echo=None, fg=None, dry_run=False):
        cf = FakeCloudflare(items)
        with mock.patch.object(app, "CloudflareClient", return_value=cf), \
             mock.patch.object(app, "FortiGateClient", return_value=fg or FakeFortiGate()), \
             mock.patch.object(detect_web, "detect", echo or fake_echo()), \
             mock.patch.object(app, "Healthchecks") as hc:
            code = app.run(self.cfg, dry_run=dry_run)
        return code, cf, hc.return_value

    def test_change_adds_then_removes_and_pings_success(self):
        items = [item("192.0.2.1"), item("198.51.100.5", comment="manual"),
                 item("2001:db8:1f::/60")]
        code, cf, hc = self.run_app(items)
        self.assertEqual(code, app.EXIT_OK)
        self.assertEqual([a["ip"] for a in cf.added], ["192.0.2.10"])
        self.assertTrue(cf.added[0]["comment"].startswith(MARKER))
        self.assertEqual(cf.deleted, ["id-192.0.2.1"])
        hc.success.assert_called_once()
        hc.fail.assert_not_called()

    def state(self):
        return json.loads((self.cfg.general.state_dir / "state.json").read_text())

    def test_ipv6_outage_keeps_v6_entry_and_fails(self):
        items = [item("192.0.2.10"), item("2001:db8:1f::/60")]
        code, cf, hc = self.run_app(items, echo=fake_echo(v6=None), fg=V6_DOWN)
        self.assertEqual(code, app.EXIT_FAILED)
        self.assertEqual(cf.deleted, [])
        hc.log.assert_called_once()

    def test_failure_threshold(self):
        self.cfg.healthchecks.failure_threshold = 3
        for n in (1, 2):
            _, _, hc = self.run_app([], echo=fake_echo(v6=None), fg=V6_DOWN)
            hc.log.assert_called_once()
            hc.fail.assert_not_called()
            self.assertEqual(self.state()["consecutive_failures"], n)
        _, _, hc = self.run_app([], echo=fake_echo(v6=None), fg=V6_DOWN)
        hc.fail.assert_called_once()
        self.assertIn("3 consecutive", hc.fail.call_args.args[0])
        _, _, hc = self.run_app([])
        hc.success.assert_called_once()
        self.assertEqual(self.state()["consecutive_failures"], 0)

    def test_dry_run_writes_nothing(self):
        code, cf, hc = self.run_app([item("192.0.2.1")], dry_run=True)
        self.assertEqual(code, app.EXIT_OK)
        self.assertEqual((cf.added, cf.deleted), ([], []))
        self.assertFalse((self.cfg.general.state_dir / "state.json").exists())
        hc.success.assert_not_called()

    def test_last_known_kept_for_undetermined_family(self):
        self.run_app([])
        self.run_app([], echo=fake_echo(v6=None), fg=V6_DOWN)
        self.assertEqual(self.state()["last_known"],
                         {"4": ["192.0.2.10"], "6": ["2001:db8:1f::/60"]})

    def test_unexpected_exception_reported(self):
        self.cfg.healthchecks.failure_threshold = 1
        with mock.patch.object(app.reconcile, "plan", side_effect=RuntimeError("bug")):
            code, _, hc = self.run_app([])
        self.assertEqual(code, app.EXIT_FAILED)
        self.assertIn("bug", hc.fail.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

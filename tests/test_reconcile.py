import ipaddress
import unittest

from cf_iplist_updater import reconcile
from cf_iplist_updater.addresses import cf_acceptable, prefix_for, to_cf

from .helpers import MARKER, item

N = ipaddress.ip_network


class PlanTests(unittest.TestCase):
    def test_empty_list_adds_both_families(self):
        p = reconcile.plan({4: [N("192.0.2.10/32")], 6: [N("2001:db8:10::/60")]}, [], MARKER)
        self.assertEqual(p.to_add, [N("192.0.2.10/32"), N("2001:db8:10::/60")])
        self.assertEqual(p.to_remove, [])

    def test_no_change(self):
        items = [item("192.0.2.10"), item("2001:db8:10::/60")]
        p = reconcile.plan({4: [N("192.0.2.10/32")], 6: [N("2001:db8:10::/60")]}, items, MARKER)
        self.assertFalse(p.changed)
        self.assertEqual(len(p.kept), 2)

    def test_ip_change_replaces_old_entry(self):
        items = [item("192.0.2.10"), item("2001:db8:10::/60")]
        p = reconcile.plan({4: [N("192.0.2.99/32")], 6: [N("2001:db8:10::/60")]}, items, MARKER)
        self.assertEqual(p.to_add, [N("192.0.2.99/32")])
        self.assertEqual([i["ip"] for i in p.to_remove], ["192.0.2.10"])

    def test_unmanaged_items_untouched(self):
        items = [item("198.51.100.7", comment="office"), item("203.0.113.0/24", comment=None)]
        p = reconcile.plan({4: [N("192.0.2.10/32")], 6: []}, items, MARKER)
        self.assertEqual(p.to_remove, [])
        self.assertEqual(p.to_add, [N("192.0.2.10/32")])

    def test_undetermined_family_is_left_alone(self):
        items = [item("192.0.2.10"), item("2001:db8:10::/60")]
        p = reconcile.plan({4: [N("192.0.2.99/32")], 6: None}, items, MARKER)
        self.assertEqual([i["ip"] for i in p.to_remove], ["192.0.2.10"])
        self.assertIn("2001:db8:10::/60", [i["ip"] for i in p.kept])

    def test_nothing_determined_removes_nothing(self):
        items = [item("192.0.2.10"), item("2001:db8:10::/60")]
        p = reconcile.plan({4: None, 6: None}, items, MARKER)
        self.assertFalse(p.changed)

    def test_disabled_family_entries_removed(self):
        items = [item("192.0.2.10"), item("2001:db8:10::/60")]
        p = reconcile.plan({4: [N("192.0.2.10/32")], 6: []}, items, MARKER)
        self.assertEqual([i["ip"] for i in p.to_remove], ["2001:db8:10::/60"])

    def test_duplicates_collapsed(self):
        items = [item("192.0.2.10", id_="a"), item("192.0.2.10/32", id_="b")]
        p = reconcile.plan({4: [N("192.0.2.10/32")], 6: None}, items, MARKER)
        self.assertEqual([i["id"] for i in p.to_remove], ["b"])
        self.assertEqual(p.to_add, [])

    def test_marker_matched_within_comment(self):
        items = [item("192.0.2.10", comment=f"{MARKER} IPv4 added 2026-01-01T00:00Z")]
        p = reconcile.plan({4: [N("192.0.2.99/32")], 6: None}, items, MARKER)
        self.assertEqual(len(p.to_remove), 1)

    def test_unparsable_managed_item_ignored(self):
        p = reconcile.plan({4: None, 6: None}, [item("not-an-ip")], MARKER)
        self.assertFalse(p.changed)


class AddressTests(unittest.TestCase):
    def test_to_cf(self):
        self.assertEqual(to_cf(N("192.0.2.10/32")), "192.0.2.10")
        self.assertEqual(to_cf(N("2001:db8:10::/60")), "2001:db8:10::/60")

    def test_prefix_for_masks_host_bits(self):
        addr = ipaddress.ip_address("2001:db8:1f:a:1234:5678:9abc:def0")
        self.assertEqual(prefix_for(addr, 60), N("2001:db8:1f::/60"))
        self.assertEqual(prefix_for(addr, 64), N("2001:db8:1f:a::/64"))

    def test_cf_acceptable(self):
        self.assertTrue(cf_acceptable(N("2001:db8::/64")))
        self.assertTrue(cf_acceptable(N("2001:db8::1/128")))
        self.assertFalse(cf_acceptable(N("2001:db8::/80")))
        self.assertFalse(cf_acceptable(N("10.0.0.0/7")))


if __name__ == "__main__":
    unittest.main()

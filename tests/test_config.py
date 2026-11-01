import os
import tempfile
import unittest
from pathlib import Path

from cf_iplist_updater import config

REPO = Path(__file__).resolve().parent.parent

VALID = """
[cloudflare]
api_token = "cf-test-token-0123456789"
account_id = "0123456789abcdef0123456789abcdef"
list_id = "fedcba9876543210fedcba9876543210"

[fortigate]
host = "fortigate.example.internal"
api_token = "fg-test-token-0123456789"
wan_interface = "wan1"
"""


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "config.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text, mode=0o600):
        self.path.write_text(text)
        os.chmod(self.path, mode)

    def test_valid_minimal(self):
        self.write(VALID)
        cfg = config.load(self.path)
        self.assertEqual(cfg.fortigate.port, 443)
        self.assertEqual(cfg.general.state_dir, Path(self.tmp.name).resolve() / "state")
        self.assertEqual(cfg.echo.quorum, 2)

    def test_rejects_group_readable(self):
        self.write(VALID, 0o640)
        with self.assertRaisesRegex(config.ConfigError, "chmod 600"):
            config.load(self.path)

    def test_rejects_placeholder(self):
        self.write(VALID.replace('list_id = "fedcba9876543210fedcba9876543210"', 'list_id = "REPLACE_ME"'))
        with self.assertRaisesRegex(config.ConfigError, "list_id"):
            config.load(self.path)

    def test_rejects_unknown_key(self):
        self.write(VALID + "\n[general]\nipv5 = true\n")
        with self.assertRaisesRegex(config.ConfigError, "ipv5"):
            config.load(self.path)

    def test_ipv6_needs_length_without_fortigate(self):
        self.write(VALID.replace('[fortigate]', '[fortigate]\nenabled = false'))
        with self.assertRaisesRegex(config.ConfigError, "prefix_length"):
            config.load(self.path)

    def test_example_config_parses_once_filled(self):
        text = (REPO / "config.example.toml").read_text().replace("REPLACE_ME", "abcdef0123456789")
        self.write(text)
        config.load(self.path)

    def assert_rejected(self, old, new, pattern):
        self.write(VALID.replace(old, new))
        with self.assertRaisesRegex(config.ConfigError, pattern):
            config.load(self.path)

    def test_rejects_wrong_types(self):
        self.assert_rejected('wan_interface = "wan1"', 'wan_interface = "wan1"\nport = "443/x"', "port must be a int")
        self.assert_rejected('wan_interface = "wan1"', 'wan_interface = "wan1"\nverify_tls = "no"', "verify_tls must be a bool")
        self.assert_rejected('wan_interface = "wan1"', 'wan_interface = "wan1"\nlan_interfaces = [1]', "list of strings")

    def test_rejects_url_and_header_injection(self):
        self.assert_rejected('host = "fortigate.example.internal"', 'host = "evil.example/x?"', "host")
        self.assert_rejected('host = "fortigate.example.internal"', 'host = "user@evil.example"', "host")
        self.assert_rejected('list_id = "fedcba9876543210fedcba9876543210"', 'list_id = "../../user"', "list_id")
        self.assert_rejected('api_token = "cf-test-token-0123456789"', 'api_token = "abc\\r\\nX-Evil: 1"', "api_token")
        self.assert_rejected('wan_interface = "wan1"', 'wan_interface = "wan1&x=1"', "wan_interface")

    def test_rejects_unsafe_urls(self):
        for url in ("http://api.ipify.org", "https://user:pw@evil.example", "ftp://x", "https://"):
            self.assert_rejected('[fortigate]', f'[echo]\nipv4_services = ["{url}"]\n\n[fortigate]', "ipv4_services")
        self.assert_rejected('[fortigate]', '[healthchecks]\nping_url = "http://hc-ping.com/x"\n\n[fortigate]', "ping_url")

    def test_rejects_short_marker(self):
        self.assert_rejected('list_id = "fedcba9876543210fedcba9876543210"',
                             'list_id = "fedcba9876543210fedcba9876543210"\ncomment_marker = "home"', "comment_marker")

    def test_bracketed_ipv6_host_allowed(self):
        self.write(VALID.replace('host = "fortigate.example.internal"', 'host = "[2001:db8::1]"'))
        config.load(self.path)


if __name__ == "__main__":
    unittest.main()

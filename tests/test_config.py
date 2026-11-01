import os
import tempfile
import unittest
from pathlib import Path

from cf_iplist_updater import config

REPO = Path(__file__).resolve().parent.parent

VALID = """
[cloudflare]
api_token = "t"
account_id = "a"
list_id = "l"

[fortigate]
host = "fortigate.example.internal"
api_token = "t"
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
        self.write(VALID.replace('list_id = "l"', 'list_id = "REPLACE_ME"'))
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
        text = (REPO / "config.example.toml").read_text().replace("REPLACE_ME", "x")
        self.write(text)
        config.load(self.path)


if __name__ == "__main__":
    unittest.main()

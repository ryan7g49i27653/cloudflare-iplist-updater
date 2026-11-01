"""Shared test fixtures. Only documentation addresses (RFC 5737 / RFC 3849).

Note: documentation ranges aren't "global", so tests that exercise the
is_public check patch it where needed.
"""

from pathlib import Path

from cf_iplist_updater import config

MARKER = "managed-by:cf-iplist-updater"


def make_config(tmp, **overrides):
    cfg = config.Config(
        path=Path(tmp) / "config.toml",
        general=config.General(state_dir=Path(tmp) / "state", log_dir=Path(tmp) / "logs"),
        cloudflare=config.Cloudflare(api_token="t", account_id="a", list_id="l"),
        fortigate=config.FortiGate(host="fortigate.example.internal", api_token="t",
                                   wan_interface="wan1"),
        echo=config.Echo(ipv4_services=["https://v4a.example", "https://v4b.example"],
                         ipv6_services=["https://v6a.example", "https://v6b.example"]),
        ipv6=config.IPv6(),
        healthchecks=config.Healthchecks(),
    )
    for dotted, value in overrides.items():
        section, key = dotted.split("__")
        setattr(getattr(cfg, section), key, value)
    return cfg


def item(ip, comment=MARKER, id_=None):
    return {"id": id_ or f"id-{ip}", "ip": ip, "comment": comment}

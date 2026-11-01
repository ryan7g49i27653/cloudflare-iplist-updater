"""Load and validate config.toml.

Every value is type-checked against its field annotation, and values that end
up in URLs or HTTP headers are checked against strict patterns.
"""

import logging
import os
import re
import stat
import tomllib
import urllib.parse
from dataclasses import dataclass, field, fields
from pathlib import Path

from . import untrusted

log = logging.getLogger(__name__)

PLACEHOLDER = "REPLACE_ME"

# One service per independent operator (ipify, ident.me, Cloudflare), so a
# quorum of 2 needs two different operators to agree.
DEFAULT_IPV4_SERVICES = [
    "https://api.ipify.org",
    "https://v4.ident.me",
    "https://1.1.1.1/cdn-cgi/trace",
]
DEFAULT_IPV6_SERVICES = [
    "https://api6.ipify.org",
    "https://v6.ident.me",
    "https://[2606:4700:4700::1111]/cdn-cgi/trace",
]

_HOST = re.compile(r"\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                   r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_INTERFACE = re.compile(r"\A[A-Za-z0-9._-]{1,35}\Z")
_TOKEN = re.compile(r"\A[A-Za-z0-9._~+/=-]{8,512}\Z")
_MARKER = re.compile(r"\A[ -~]{8,100}\Z")


class ConfigError(Exception):
    pass


@dataclass
class General:
    ipv4: bool = True
    ipv6: bool = True
    state_dir: Path = Path("state")
    log_dir: Path = Path("logs")


@dataclass
class Cloudflare:
    api_token: str = ""
    account_id: str = ""
    list_id: str = ""
    comment_marker: str = "managed-by:cf-iplist-updater"
    timeout: float = 15


@dataclass
class FortiGate:
    enabled: bool = True
    host: str = ""
    port: int = 443
    api_token: str = ""
    wan_interface: str = ""
    lan_interfaces: list = field(default_factory=list)  # empty = all non-WAN interfaces
    ca_file: str = ""
    verify_tls: bool = True
    timeout: float = 10


@dataclass
class Echo:
    quorum: int = 2
    timeout: float = 8
    ipv4_services: list = field(default_factory=lambda: list(DEFAULT_IPV4_SERVICES))
    ipv6_services: list = field(default_factory=lambda: list(DEFAULT_IPV6_SERVICES))


@dataclass
class IPv6:
    fallback_prefix_length: int = 0  # 0 = length of the last known prefix


@dataclass
class Healthchecks:
    ping_url: str = ""
    failure_threshold: int = 3
    timeout: float = 10


@dataclass
class Config:
    path: Path
    general: General
    cloudflare: Cloudflare
    fortigate: FortiGate
    echo: Echo
    ipv6: IPv6
    healthchecks: Healthchecks


def _type_ok(value, annotation):
    if annotation is bool:
        return isinstance(value, bool)
    if annotation is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if annotation is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if annotation in (str, Path):
        return isinstance(value, str)
    if annotation is list:
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    return False


def _section(cls, raw, name):
    data = raw.get(name, {})
    if not isinstance(data, dict):
        raise ConfigError(f"[{name}] must be a table")
    types = {f.name: f.type for f in fields(cls)}
    unknown = set(data) - set(types)
    if unknown:
        raise ConfigError(f"unknown key(s) in [{name}]: {', '.join(sorted(unknown))}")
    for key, value in data.items():
        if not _type_ok(value, types[key]):
            expected = "list of strings" if types[key] is list else types[key].__name__
            raise ConfigError(f"[{name}] {key} must be a {expected}")
    return cls(**data)


def check_permissions(path):
    mode = os.stat(path).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{path} is accessible by group/other (mode {stat.filemode(mode)}); "
                          f"run: chmod 600 {path}")


def load(path, check_perms=True):
    path = Path(path).resolve()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    if check_perms:
        check_permissions(path)
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None

    unknown = set(raw) - {"general", "cloudflare", "fortigate", "echo", "ipv6", "healthchecks"}
    if unknown:
        raise ConfigError(f"unknown section(s): {', '.join(sorted(unknown))}")
    try:
        cfg = Config(
            path=path,
            general=_section(General, raw, "general"),
            cloudflare=_section(Cloudflare, raw, "cloudflare"),
            fortigate=_section(FortiGate, raw, "fortigate"),
            echo=_section(Echo, raw, "echo"),
            ipv6=_section(IPv6, raw, "ipv6"),
            healthchecks=_section(Healthchecks, raw, "healthchecks"),
        )
    except TypeError as e:
        raise ConfigError(str(e)) from None

    # Relative directories are relative to the config file.
    base = path.parent
    cfg.general.state_dir = base / Path(cfg.general.state_dir)
    cfg.general.log_dir = base / Path(cfg.general.log_dir)
    if cfg.fortigate.ca_file:
        cfg.fortigate.ca_file = str(base / Path(cfg.fortigate.ca_file))
        if not Path(cfg.fortigate.ca_file).is_file():
            raise ConfigError(f"[fortigate] ca_file not found: {cfg.fortigate.ca_file}")
    validate(cfg)
    return cfg


def _require(section, obj, *names):
    for name in names:
        value = getattr(obj, name)
        if not value or value == PLACEHOLDER:
            raise ConfigError(f"[{section}] {name} must be set")


def validate(cfg):
    if not (cfg.general.ipv4 or cfg.general.ipv6):
        raise ConfigError("[general] at least one of ipv4/ipv6 must be enabled")
    _require("cloudflare", cfg.cloudflare, "api_token", "account_id", "list_id", "comment_marker")
    if cfg.fortigate.enabled:
        _require("fortigate", cfg.fortigate, "host", "api_token", "wan_interface")
    if cfg.echo.quorum < 1:
        raise ConfigError("[echo] quorum must be >= 1")
    if cfg.general.ipv4 and len(cfg.echo.ipv4_services) < cfg.echo.quorum and not cfg.fortigate.enabled:
        raise ConfigError("[echo] fewer ipv4_services than quorum and FortiGate disabled")
    if cfg.general.ipv6 and len(cfg.echo.ipv6_services) < cfg.echo.quorum and not cfg.fortigate.enabled:
        raise ConfigError("[echo] fewer ipv6_services than quorum and FortiGate disabled")
    if cfg.ipv6.fallback_prefix_length and not 12 <= cfg.ipv6.fallback_prefix_length <= 64:
        raise ConfigError("[ipv6] fallback_prefix_length must be 0 (last known) or 12-64")
    if cfg.general.ipv6 and not cfg.ipv6.fallback_prefix_length and not cfg.fortigate.enabled:
        raise ConfigError("[ipv6] fallback_prefix_length must be set when FortiGate is disabled")
    if cfg.healthchecks.failure_threshold < 1:
        raise ConfigError("[healthchecks] failure_threshold must be >= 1")
    validate_values(cfg)


def _https_url(section, key, url):
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme != "https" or not parts.hostname or "@" in parts.netloc
            or parts.fragment or any(not " " < c <= "~" for c in url)):
        raise ConfigError(f"[{section}] {key}: must be a plain https:// URL "
                          f"(got {untrusted.describe(url, 60)})")


def _pattern(section, key, value, pattern, what):
    if not pattern.match(value):
        raise ConfigError(f"[{section}] {key} is not a valid {what}")


def validate_values(cfg):
    """Strict checks on values that end up in URLs, headers or deletions."""
    cf, fg, hc = cfg.cloudflare, cfg.fortigate, cfg.healthchecks
    for key in ("account_id", "list_id"):
        try:
            untrusted.opaque_id(getattr(cf, key))
        except untrusted.UntrustedDataError:
            raise ConfigError(f"[cloudflare] {key} is not a valid ID") from None
    _pattern("cloudflare", "api_token", cf.api_token, _TOKEN, "token")
    # Items are deleted when their comment contains the marker, so a short or
    # generic marker could match (and remove) entries added by hand.
    _pattern("cloudflare", "comment_marker", cf.comment_marker, _MARKER,
             "marker (8-100 printable ASCII characters)")

    if fg.enabled:
        host = fg.host[1:-1] if fg.host.startswith("[") and fg.host.endswith("]") else fg.host
        try:
            untrusted.ip_address(host)
        except untrusted.UntrustedDataError:
            _pattern("fortigate", "host", host, _HOST, "hostname or IP address")
        if not 1 <= fg.port <= 65535:
            raise ConfigError("[fortigate] port must be 1-65535")
        _pattern("fortigate", "api_token", fg.api_token, _TOKEN, "token")
        _pattern("fortigate", "wan_interface", fg.wan_interface, _INTERFACE, "interface name")
        for name in fg.lan_interfaces:
            _pattern("fortigate", "lan_interfaces", name, _INTERFACE, "interface name")
        if not fg.verify_tls:
            log.warning("[fortigate] verify_tls = false: the FortiGate API token is sent "
                        "without certificate verification")

    for key in ("ipv4_services", "ipv6_services"):
        for url in getattr(cfg.echo, key):
            _https_url("echo", key, url)
    if cfg.echo.quorum < 2:
        log.warning("[echo] quorum = 1: a single echo service can decide the fallback address")
    if hc.ping_url:
        _https_url("healthchecks", "ping_url", hc.ping_url)

    for section, obj in (("cloudflare", cf), ("fortigate", fg), ("echo", cfg.echo),
                         ("healthchecks", hc)):
        if not 0 < obj.timeout <= 120:
            raise ConfigError(f"[{section}] timeout must be between 0 and 120 seconds")

"""FortiGate REST API queries (verified against FortiOS 7.6).

- WAN IPv4: GET /api/v2/monitor/system/interface?interface_name=<wan>
  &include_vlan=true&include_aggregate=true
- Delegated IPv6 prefixes: GET /api/v2/monitor/router/ipv6. The prefix the ISP
  delegates isn't in the REST API directly (only in the CLI), but each
  downstream interface using it has a connected route for its subnet, e.g.
  {"interface": "LAN", "ip_mask": "2001:db8:1f::/64", "type": "connect"}.
  Every global, non-host connected route on a non-WAN interface is treated
  as a delegated prefix.
"""

import ipaddress
import logging
import urllib.parse

from . import httpclient
from .addresses import is_public

log = logging.getLogger(__name__)


class FortiGateError(Exception):
    pass


def _check_status(payload, what):
    if payload.get("status") == "error":
        raise FortiGateError(f"{what}: API error HTTP {payload.get('http_status')} "
                             "(403 = admin profile lacks read access)")


def parse_wan_ipv4(payload, interface):
    """Extract the interface's IPv4 address from a monitor/system/interface response."""
    _check_status(payload, "monitor/system/interface")
    results = payload.get("results")
    if isinstance(results, dict):
        entry = results.get(interface)
    elif isinstance(results, list):
        entry = next((r for r in results if r.get("name") == interface), None)
    else:
        entry = None
    if not entry:
        raise FortiGateError(f"interface {interface!r} not in monitor response")
    ip = entry.get("ip")
    if not ip or ip == "0.0.0.0":
        raise FortiGateError(f"interface {interface!r} has no IPv4 address")
    return ipaddress.IPv4Address(ip)


def parse_delegated_prefixes(payload, wan_interface, lan_interfaces=()):
    """Global connected IPv6 subnets on downstream interfaces, sorted and de-duplicated.

    lan_interfaces, if given, limits which interfaces are considered.
    """
    _check_status(payload, "monitor/router/ipv6")
    nets = set()
    for route in payload.get("results") or []:
        iface = route.get("interface")
        if route.get("type") != "connect" or iface == wan_interface:
            continue
        if lan_interfaces and iface not in lan_interfaces:
            continue
        try:
            net = ipaddress.IPv6Network(route.get("ip_mask", ""), strict=False)
        except ValueError:
            continue
        if net.prefixlen < 128 and is_public(net.network_address):
            nets.add(net)
    return sorted(nets)


class FortiGateClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = f"https://{cfg.host}:{cfg.port}/api/v2"
        self.ssl = httpclient.make_ssl_context(cfg.ca_file, cfg.verify_tls)

    def get(self, path, params=None):
        url = f"{self.base}/{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        try:
            return httpclient.request_json(
                "GET", url, timeout=self.cfg.timeout, ssl_context=self.ssl,
                headers={"Authorization": f"Bearer {self.cfg.api_token}"},
                label=f"fortigate {path}")
        except httpclient.HTTPError as e:
            raise FortiGateError(str(e)) from None

    def monitor_interface(self):
        # Without the include_* flags, VLAN and aggregate/redundant interfaces
        # are silently left out of the results.
        return self.get("monitor/system/interface", {
            "interface_name": self.cfg.wan_interface,
            "include_vlan": "true",
            "include_aggregate": "true",
        })

    def ipv6_routes(self):
        return self.get("monitor/router/ipv6")

    def wan_ipv4(self):
        return parse_wan_ipv4(self.monitor_interface(), self.cfg.wan_interface)

    def delegated_prefixes(self):
        return parse_delegated_prefixes(self.ipv6_routes(), self.cfg.wan_interface,
                                        self.cfg.lan_interfaces)

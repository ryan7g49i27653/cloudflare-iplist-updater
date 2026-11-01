"""Address validation and normalization shared by detection and reconcile."""

import ipaddress

from . import untrusted

# Cloudflare IP Lists accept IPv4 /8-/32 and IPv6 /12-/64 (or a single /128).
CF_V4_RANGE = (8, 32)
CF_V6_RANGE = (12, 64)


def is_public(addr):
    """True for globally routable unicast addresses (excludes CGNAT, ULA, etc.)."""
    return addr.is_global and not addr.is_multicast


def parse_network(value):
    """Strictly parse a list-item 'ip' value ('192.0.2.1', '2001:db8::/48').

    Raises untrusted.UntrustedDataError (a ValueError) on anything else.
    """
    return untrusted.ip_network(value)


def to_cf(net):
    """Cloudflare's canonical item form: bare address for host routes, else CIDR."""
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return net.with_prefixlen


def cf_acceptable(net):
    if net.prefixlen == net.max_prefixlen:
        return True
    lo, hi = CF_V4_RANGE if net.version == 4 else CF_V6_RANGE
    return lo <= net.prefixlen <= hi


def prefix_for(addr, prefix_length):
    """The network of the given length that contains addr."""
    return ipaddress.ip_network(f"{addr}/{prefix_length}", strict=False)

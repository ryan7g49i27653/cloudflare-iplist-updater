"""Public-address detection via IP echo services, with a quorum."""

import ipaddress
import logging
from collections import Counter

from . import httpclient
from .addresses import is_public

log = logging.getLogger(__name__)


def parse_echo(text):
    """Accept a bare address or Cloudflare's /cdn-cgi/trace 'key=value' format."""
    for line in text.splitlines():
        if line.startswith("ip="):
            return ipaddress.ip_address(line[3:].strip())
    return ipaddress.ip_address(text.strip())


def fetch(url, timeout):
    _, body = httpclient.request("GET", url, timeout=timeout, retries=1)
    return parse_echo(body.decode("utf-8", "replace"))


def detect(version, services, quorum, timeout):
    """Return the address at least `quorum` services agree on, or None.

    `services` should be single-stack endpoints for `version`, since urllib
    can't force an address family.
    """
    votes = Counter()
    for url in services:
        label = httpclient.safe_label(url)
        try:
            addr = fetch(url, timeout)
        except (httpclient.HTTPError, ValueError) as e:
            log.warning("echo %s: %s", label, e)
            continue
        if addr.version != version or not is_public(addr):
            log.warning("echo %s returned unusable IPv%d answer %s", label, version, addr)
            continue
        log.debug("echo %s -> %s", label, addr)
        votes[addr] += 1
        if votes[addr] >= quorum:
            return addr
    if votes:
        log.warning("IPv%d echo services did not reach quorum %d: %s", version, quorum,
                    ", ".join(f"{a} x{n}" for a, n in votes.items()))
    return None

"""Public-address detection via IP echo services, with a quorum.

Echo services are untrusted. A response is accepted only if it is HTTP 200,
text/plain, at most MAX_BODY bytes of printable ASCII, and contains exactly
one address: either the whole body (ignoring surrounding whitespace) or
exactly one "ip=" line in Cloudflare's /cdn-cgi/trace format. The address
then has to pass `untrusted.ip_address` and be globally routable.
"""

import logging
from collections import Counter

from . import httpclient, untrusted
from .addresses import is_public

log = logging.getLogger(__name__)

MAX_BODY = 1024


def parse_echo(body):
    """Return the single address in an echo response body (bytes)."""
    text = untrusted.text_body(body, MAX_BODY)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    ip_lines = [line[3:] for line in lines if line.startswith("ip=")]
    if ip_lines:
        if len(ip_lines) != 1:
            raise untrusted.UntrustedDataError("multiple ip= lines")
        return untrusted.ip_address(ip_lines[0])
    if len(lines) != 1:
        raise untrusted.UntrustedDataError("expected exactly one line")
    return untrusted.ip_address(lines[0])


def fetch(url, timeout):
    resp = httpclient.request("GET", url, timeout=timeout, retries=1, max_bytes=MAX_BODY)
    if resp.status != 200:
        raise untrusted.UntrustedDataError(f"unexpected HTTP status {resp.status}")
    if resp.content_type.split(";")[0].strip().lower() != "text/plain":
        raise untrusted.UntrustedDataError(
            f"unexpected content type {untrusted.describe(resp.content_type, 40)}")
    return parse_echo(resp.body)


def detect(version, services, quorum, timeout):
    """Return the address at least `quorum` services agree on, or None.

    `services` should be single-stack endpoints for `version`, run by
    independent operators, since urllib can't force an address family.
    """
    votes = Counter()
    for url in services:
        label = httpclient.safe_label(url)
        try:
            addr = fetch(url, timeout)
        except (httpclient.HTTPError, untrusted.UntrustedDataError) as e:
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

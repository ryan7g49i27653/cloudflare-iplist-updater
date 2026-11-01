"""Strict handling of data received from the network.

Rules for everything that crosses this boundary:

- Values are matched against a strict allowlist pattern (type, characters,
  length) before any parsing. Anything else is rejected, not cleaned up.
- Addresses are then parsed with `ipaddress`, and only the canonical
  re-serialized form is used afterwards. Raw response strings never reach
  Cloudflare, the logs or Healthchecks.
- Error messages never include the rejected input; `describe()` produces a
  short, escaped, printable-ASCII rendering when something must be shown.
"""

import ipaddress
import re

# Plain dotted-quad. Leading zeros and range are left to ipaddress, which
# rejects both.
_V4 = re.compile(r"\A(?:[0-9]{1,3}\.){3}[0-9]{1,3}\Z")
# Hex and colons only: no scope IDs ("%eth0"), no embedded dotted quads,
# no whitespace.
_V6 = re.compile(r"\A[0-9A-Fa-f:]{2,39}\Z")
_PREFIXLEN = re.compile(r"\A[0-9]{1,3}\Z")
# Cloudflare account/list/item/operation IDs: opaque tokens that end up in
# URL paths, so path and query characters are never allowed.
_OPAQUE_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")


class UntrustedDataError(ValueError):
    """Raised for rejected input. The message never contains the input itself."""


def describe(value, limit=80):
    """Printable-ASCII rendering of any value for logs: escaped and truncated."""
    text = value if isinstance(value, str) else repr(value)
    out = []
    for ch in text:
        if " " <= ch <= "~":
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}")
    rendered = "".join(out)
    return rendered if len(rendered) <= limit else rendered[:limit] + "..."


def ip_address(value, version=None):
    """Strictly parse a bare IPv4/IPv6 address string."""
    if not isinstance(value, str):
        raise UntrustedDataError(f"expected an address string, got {type(value).__name__}")
    if not (_V4.match(value) or _V6.match(value)):
        raise UntrustedDataError("not a plain IPv4/IPv6 address")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise UntrustedDataError("invalid IP address") from None
    if version and addr.version != version:
        raise UntrustedDataError(f"expected IPv{version}, got IPv{addr.version}")
    return addr


def ip_network(value, version=None):
    """Strictly parse 'address' or 'address/prefixlen' (host bits are masked off)."""
    if not isinstance(value, str):
        raise UntrustedDataError(f"expected a network string, got {type(value).__name__}")
    addr_part, sep, length_part = value.partition("/")
    if sep and not _PREFIXLEN.match(length_part):
        raise UntrustedDataError("invalid prefix length")
    addr = ip_address(addr_part, version)
    try:
        return ipaddress.ip_network(f"{addr}/{length_part}" if sep else str(addr), strict=False)
    except ValueError:
        raise UntrustedDataError("invalid network") from None


def opaque_id(value):
    """Validate an ID that will be placed in a URL path or request body."""
    if not isinstance(value, str) or not _OPAQUE_ID.match(value):
        raise UntrustedDataError("invalid identifier")
    return value


def text_body(body, max_bytes):
    """Decode a small plain-text response: printable ASCII and line breaks only."""
    if len(body) > max_bytes:
        raise UntrustedDataError(f"response larger than {max_bytes} bytes")
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        raise UntrustedDataError("response contains non-ASCII bytes") from None
    if any(not (" " <= ch <= "~" or ch in "\r\n") for ch in text):
        raise UntrustedDataError("response contains control characters")
    return text

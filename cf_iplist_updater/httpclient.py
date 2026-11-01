"""Minimal urllib wrapper: timeouts, retries with backoff, JSON, TLS options.

Logging never includes request headers, query strings or bodies, so tokens
and Healthchecks UUIDs stay out of the logs.
"""

import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"cf-iplist-updater/{__version__}"
RETRY_STATUSES = {429, 500, 502, 503, 504}


class HTTPError(Exception):
    def __init__(self, message, status=None, body=b""):
        super().__init__(message)
        self.status = status
        self.body = body


def make_ssl_context(ca_file=None, verify=True):
    """System trust store, plus ca_file if given (e.g. intermediates a server
    fails to send). ca_file adds to the store rather than replacing it."""
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def safe_label(url):
    """Host and path only, for logs."""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def request(method, url, *, headers=None, json_body=None, data=None, timeout=10,
            retries=2, backoff=1.0, ssl_context=None, label=None):
    """Perform a request and return (status, body bytes).

    Retries network errors and 429/5xx responses; other HTTP errors raise
    immediately.
    """
    label = label or safe_label(url)
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    elif isinstance(data, str):
        data = data.encode()

    attempt = 0
    while True:
        attempt += 1
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            body = e.read() if e.fp else b""
            if e.code not in RETRY_STATUSES or attempt > retries:
                raise HTTPError(f"{method} {label}: HTTP {e.code}", e.code, body) from None
            reason = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError) as e:
            if attempt > retries:
                raise HTTPError(f"{method} {label}: {getattr(e, 'reason', e)}") from None
            reason = str(getattr(e, "reason", e))
        delay = backoff * 2 ** (attempt - 1)
        log.debug("%s %s failed (%s); retrying in %.1fs", method, label, reason, delay)
        time.sleep(delay)


def request_json(method, url, **kwargs):
    label = kwargs.get("label") or safe_label(url)
    status, body = request(method, url, **kwargs)
    try:
        return json.loads(body)
    except ValueError:
        raise HTTPError(f"{method} {label}: response is not JSON", status, body) from None

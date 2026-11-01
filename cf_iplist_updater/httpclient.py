"""Minimal urllib wrapper: HTTPS only, no redirects, size-capped, retries.

- Redirects are refused. urllib would otherwise follow them to any host and
  forward the Authorization header, leaking API tokens.
- Only https:// URLs are allowed, with TLS 1.2 or newer and certificate checks
  unless a caller explicitly passes an unverified context.
- Response bodies are capped (max_bytes); larger responses are an error, not
  truncated data.
- Logging never includes request headers, query strings or bodies, so tokens
  and Healthchecks UUIDs stay out of the logs.
"""

import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from . import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"cf-iplist-updater/{__version__}"
RETRY_STATUSES = {429, 500, 502, 503, 504}
DEFAULT_MAX_BYTES = 2_000_000


class HTTPError(Exception):
    def __init__(self, message, status=None, body=b""):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class Response:
    status: int
    body: bytes
    content_type: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirect refused ({code})", headers, fp)


def make_ssl_context(ca_file=None, verify=True):
    """System trust store, plus ca_file if given (e.g. intermediates a server
    fails to send). ca_file adds to the store rather than replacing it."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


_DEFAULT_CONTEXT = None


def _opener(ssl_context):
    global _DEFAULT_CONTEXT
    if ssl_context is None:
        if _DEFAULT_CONTEXT is None:
            _DEFAULT_CONTEXT = make_ssl_context()
        ssl_context = _DEFAULT_CONTEXT
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context),
                                       _NoRedirect())


def safe_label(url):
    """Host and path only, for logs."""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _read_capped(resp, max_bytes, label):
    body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise HTTPError(f"{label}: response larger than {max_bytes} bytes")
    return body


def request(method, url, *, headers=None, json_body=None, data=None, timeout=10,
            retries=2, backoff=1.0, ssl_context=None, label=None,
            max_bytes=DEFAULT_MAX_BYTES):
    """Perform a request and return a Response.

    Retries network errors and 429/5xx responses; other HTTP errors raise
    immediately.
    """
    label = label or safe_label(url)
    if urllib.parse.urlsplit(url).scheme != "https":
        raise HTTPError(f"{method} {label}: only https:// URLs are allowed")
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    elif isinstance(data, str):
        data = data.encode()
    opener = _opener(ssl_context)

    attempt = 0
    while True:
        attempt += 1
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = _read_capped(resp, max_bytes, f"{method} {label}")
                return Response(resp.status, body, resp.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as e:
            body = b""
            if e.fp:
                try:
                    body = e.read(64_000)
                except OSError:
                    pass
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
    """Request and decode a JSON object response."""
    label = kwargs.get("label") or safe_label(url)
    resp = request(method, url, **kwargs)
    try:
        payload = json.loads(resp.body)
    except ValueError:
        raise HTTPError(f"{method} {label}: response is not JSON", resp.status, resp.body) from None
    if not isinstance(payload, dict):
        raise HTTPError(f"{method} {label}: expected a JSON object", resp.status)
    return payload

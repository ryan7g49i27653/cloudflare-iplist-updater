"""Cloudflare account-level IP List client.

Docs: https://developers.cloudflare.com/api/resources/rules/subresources/lists/
Item writes are asynchronous bulk operations that must be polled.

Cloudflare is trusted, but responses are still shape-checked: IDs that go
back into URLs or request bodies must pass `untrusted.opaque_id`, and error
text is escaped before it is logged or reported.
"""

import json
import logging
import time
import urllib.parse

from . import httpclient, untrusted

log = logging.getLogger(__name__)

API = "https://api.cloudflare.com/client/v4"
MAX_PAGES = 100  # 500 items/page; guards against a cursor that never ends


class CloudflareError(Exception):
    pass


class CloudflareClient:
    def __init__(self, cfg, poll_interval=1.0, poll_timeout=90):
        self.cfg = cfg
        self.base = f"{API}/accounts/{untrusted.opaque_id(cfg.account_id)}/rules/lists"
        self.list_path = f"/{untrusted.opaque_id(cfg.list_id)}"
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout

    def _call(self, method, path="", body=None, params=None):
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        label = f"cloudflare lists{path}"
        try:
            payload = httpclient.request_json(
                method, url, json_body=body, timeout=self.cfg.timeout, label=label,
                headers={"Authorization": f"Bearer {self.cfg.api_token}"})
        except httpclient.HTTPError as e:
            raise CloudflareError(f"{e}{_errors_from_body(e.body)}") from None
        if payload.get("success") is not True:
            raise CloudflareError(f"{label}: {_format_errors(payload.get('errors'))}")
        return payload

    def _result(self, payload, kind):
        result = payload.get("result")
        if not isinstance(result, kind):
            raise CloudflareError(f"unexpected response shape (result is not {kind.__name__})")
        return result

    def get_list(self):
        return self._result(self._call("GET", self.list_path), dict)

    def list_items(self):
        items, cursor = [], None
        for _ in range(MAX_PAGES):
            params = {"per_page": 500}
            if cursor:
                params["cursor"] = cursor
            payload = self._call("GET", f"{self.list_path}/items", params=params)
            items.extend(i for i in self._result(payload, list) if isinstance(i, dict))
            cursors = (payload.get("result_info") or {}).get("cursors") or {}
            cursor = cursors.get("after") if isinstance(cursors, dict) else None
            if not cursor:
                return items
            if not isinstance(cursor, str) or len(cursor) > 1024:
                raise CloudflareError("invalid pagination cursor")
        raise CloudflareError(f"list has more than {MAX_PAGES} pages; refusing to continue")

    def add_items(self, items):
        """items: [{"ip": "...", "comment": "..."}]; appends without touching others."""
        payload = self._call("POST", f"{self.list_path}/items", body=items)
        self.wait(self._operation_id(payload))

    def delete_items(self, item_ids):
        body = {"items": [{"id": untrusted.opaque_id(i)} for i in item_ids]}
        payload = self._call("DELETE", f"{self.list_path}/items", body=body)
        self.wait(self._operation_id(payload))

    def _operation_id(self, payload):
        try:
            return untrusted.opaque_id(self._result(payload, dict).get("operation_id"))
        except untrusted.UntrustedDataError:
            raise CloudflareError("invalid bulk operation id") from None

    def wait(self, operation_id):
        deadline = time.monotonic() + self.poll_timeout
        while True:
            op = self._result(self._call("GET", f"/bulk_operations/{operation_id}"), dict)
            status = op.get("status")
            if status == "completed":
                return
            if status == "failed":
                raise CloudflareError(f"bulk operation {operation_id} failed: "
                                      f"{untrusted.describe(op.get('error'), 200)}")
            if time.monotonic() > deadline:
                raise CloudflareError(f"bulk operation {operation_id} still "
                                      f"{untrusted.describe(status, 20)} after {self.poll_timeout}s")
            time.sleep(self.poll_interval)


def _format_errors(errors):
    if not isinstance(errors, list) or not errors:
        return "unsuccessful response"
    parts = []
    for e in errors[:5]:
        if isinstance(e, dict):
            code = e.get("code") if isinstance(e.get("code"), int) else "?"
            parts.append(f"[{code}] {untrusted.describe(e.get('message'), 200)}")
    return "; ".join(parts) or "unsuccessful response"


def _errors_from_body(body):
    try:
        return " - " + _format_errors(json.loads(body).get("errors"))
    except (ValueError, AttributeError):
        return ""

"""Cloudflare account-level IP List client.

Docs: https://developers.cloudflare.com/api/resources/rules/subresources/lists/
Item writes are asynchronous bulk operations that must be polled.
"""

import json
import logging
import time
import urllib.parse

from . import httpclient

log = logging.getLogger(__name__)

API = "https://api.cloudflare.com/client/v4"


class CloudflareError(Exception):
    pass


class CloudflareClient:
    def __init__(self, cfg, poll_interval=1.0, poll_timeout=90):
        self.cfg = cfg
        self.base = f"{API}/accounts/{cfg.account_id}/rules/lists"
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
        if not payload.get("success", False):
            raise CloudflareError(f"{label}: {_format_errors(payload.get('errors'))}")
        return payload

    def get_list(self):
        return self._call("GET", f"/{self.cfg.list_id}")["result"]

    def list_items(self):
        items, cursor = [], None
        while True:
            params = {"per_page": 500}
            if cursor:
                params["cursor"] = cursor
            payload = self._call("GET", f"/{self.cfg.list_id}/items", params=params)
            items.extend(payload.get("result") or [])
            cursor = ((payload.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cursor:
                return items

    def add_items(self, items):
        """items: [{"ip": "...", "comment": "..."}]; appends without touching others."""
        payload = self._call("POST", f"/{self.cfg.list_id}/items", body=items)
        self.wait(payload["result"]["operation_id"])

    def delete_items(self, item_ids):
        body = {"items": [{"id": i} for i in item_ids]}
        payload = self._call("DELETE", f"/{self.cfg.list_id}/items", body=body)
        self.wait(payload["result"]["operation_id"])

    def wait(self, operation_id):
        deadline = time.monotonic() + self.poll_timeout
        while True:
            op = self._call("GET", f"/bulk_operations/{operation_id}")["result"]
            status = op.get("status")
            if status == "completed":
                return
            if status == "failed":
                raise CloudflareError(f"bulk operation {operation_id} failed: {op.get('error')}")
            if time.monotonic() > deadline:
                raise CloudflareError(f"bulk operation {operation_id} still {status} after "
                                      f"{self.poll_timeout}s")
            time.sleep(self.poll_interval)


def _format_errors(errors):
    if not errors:
        return "unsuccessful response"
    return "; ".join(f"[{e.get('code')}] {e.get('message')}" for e in errors)


def _errors_from_body(body):
    try:
        return " - " + _format_errors(json.loads(body).get("errors"))
    except (ValueError, AttributeError):
        return ""

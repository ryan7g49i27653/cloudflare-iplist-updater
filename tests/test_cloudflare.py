import json
import unittest
from unittest import mock

from cf_iplist_updater import cloudflare, httpclient
from cf_iplist_updater.config import Cloudflare


def ok(result, **extra):
    return {"success": True, "errors": [], "result": result, **extra}


class CloudflareTests(unittest.TestCase):
    def setUp(self):
        self.cf = cloudflare.CloudflareClient(
            Cloudflare(api_token="t", account_id="acct", list_id="lst"), poll_interval=0)

    def test_list_items_paginates(self):
        pages = [ok([{"id": "1"}], result_info={"cursors": {"after": "c2"}}),
                 ok([{"id": "2"}], result_info={"cursors": {}})]
        with mock.patch.object(httpclient, "request_json", side_effect=pages) as rj:
            self.assertEqual([i["id"] for i in self.cf.list_items()], ["1", "2"])
        self.assertIn("cursor=c2", rj.call_args_list[1].args[1])

    def test_add_items_waits_for_operation(self):
        responses = [ok({"operation_id": "op"}), ok({"status": "pending"}),
                     ok({"status": "completed"})]
        with mock.patch.object(httpclient, "request_json", side_effect=responses) as rj:
            self.cf.add_items([{"ip": "192.0.2.10", "comment": "x"}])
        method, url = rj.call_args_list[0].args
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/accounts/acct/rules/lists/lst/items"))
        self.assertTrue(rj.call_args_list[2].args[1].endswith("/bulk_operations/op"))

    def test_delete_body(self):
        responses = [ok({"operation_id": "op"}), ok({"status": "completed"})]
        with mock.patch.object(httpclient, "request_json", side_effect=responses) as rj:
            self.cf.delete_items(["a", "b"])
        self.assertEqual(rj.call_args_list[0].kwargs["json_body"],
                         {"items": [{"id": "a"}, {"id": "b"}]})

    def test_failed_operation_raises(self):
        responses = [ok({"operation_id": "op"}), ok({"status": "failed", "error": "bad ip"})]
        with mock.patch.object(httpclient, "request_json", side_effect=responses):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "bad ip"):
                self.cf.add_items([{"ip": "x"}])

    def test_http_error_includes_api_message(self):
        body = json.dumps({"success": False, "errors": [{"code": 10000, "message": "Auth"}]})
        err = httpclient.HTTPError("GET x: HTTP 403", 403, body.encode())
        with mock.patch.object(httpclient, "request_json", side_effect=err):
            with self.assertRaisesRegex(cloudflare.CloudflareError, r"\[10000\] Auth"):
                self.cf.get_list()


if __name__ == "__main__":
    unittest.main()

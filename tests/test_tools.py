"""Tests for tool handlers and the receipt store."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from receipts import ReceiptStore
from tools import (
    secret_scan,
    make_secret_gate_check,
    make_secret_gate_receipts,
    make_slash_scan,
)


class TestSecretScanHandler(unittest.TestCase):
    def test_returns_json_string(self):
        out = secret_scan({"text": "hello"})
        data = json.loads(out)
        self.assertEqual(data["verdict"], "CLEAR")

    def test_leaked(self):
        out = secret_scan({"text": "key = AKIAIOSFODNN7EXAMPLE"})
        self.assertEqual(json.loads(out)["verdict"], "LEAKED")

    def test_never_raises(self):
        self.assertIn("error", json.loads(secret_scan({"text": 123})))
        # Missing text scans as empty input, not an error.
        self.assertEqual(json.loads(secret_scan({}))["verdict"], "CLEAR")

    def test_no_secret_in_output(self):
        secret = "ghp_abcdefghij1234567890ABCD"
        out = secret_scan({"text": f"token = {secret}"})
        self.assertNotIn(secret, out)


class TestGateCheck(unittest.TestCase):
    def setUp(self):
        self.store = ReceiptStore()
        self.check = make_secret_gate_check(self.store)

    def test_clear_allows(self):
        data = json.loads(self.check({"text": "hello world"}))
        self.assertEqual(data["gate"], "ALLOW")
        self.assertTrue(data["receipt_id"].startswith("HSG-"))

    def test_leaked_blocks(self):
        data = json.loads(
            self.check({"text": "AKIAIOSFODNN7EXAMPLE", "destination": "github issue"})
        )
        self.assertEqual(data["gate"], "BLOCK")
        self.assertEqual(data["destination"], "github issue")
        self.assertIn("never be approved", data["note"])

    def test_review_warns(self):
        data = json.loads(self.check({"text": "open('/home/dev/.ssh/id_ed25519')"}))
        self.assertEqual(data["gate"], "WARN")

    def test_receipt_recorded(self):
        self.check({"text": "AKIAIOSFODNN7EXAMPLE"})
        receipts = self.store.list_recent(10)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["gate"], "BLOCK")
        self.assertEqual(receipts[0]["rules"], ["aws_access_key"])


class TestReceiptsHandler(unittest.TestCase):
    def test_list_and_limit(self):
        store = ReceiptStore()
        check = make_secret_gate_check(store)
        for _ in range(3):
            check({"text": "AKIAIOSFODNN7EXAMPLE"})
        handler = make_secret_gate_receipts(store)
        data = json.loads(handler({"limit": 2}))
        self.assertEqual(data["count"], 2)
        data = json.loads(handler({}))
        self.assertEqual(data["count"], 3)

    def test_bad_limit_defaults(self):
        store = ReceiptStore()
        handler = make_secret_gate_receipts(store)
        self.assertEqual(json.loads(handler({"limit": "junk"}))["count"], 0)


class TestSlashCommand(unittest.TestCase):
    def test_usage_when_empty(self):
        store = ReceiptStore()
        handle = make_slash_scan(store)
        self.assertIn("Usage", handle(""))

    def test_block_reply(self):
        store = ReceiptStore()
        handle = make_slash_scan(store)
        reply = handle("AKIAIOSFODNN7EXAMPLE")
        self.assertIn("LEAKED", reply)
        self.assertIn("Do not send", reply)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", reply)

    def test_clear_reply(self):
        store = ReceiptStore()
        handle = make_slash_scan(store)
        self.assertIn("CLEAR", handle("hello world"))


class TestReceiptRing(unittest.TestCase):
    def test_bounded(self):
        store = ReceiptStore(max_receipts=3)
        for _ in range(5):
            store.record("gate_check", "CLEAR", "ALLOW", [])
        self.assertEqual(len(store.list_recent(50)), 3)

    def test_receipt_ids_unique(self):
        store = ReceiptStore()
        ids = {store.record("gate_check", "CLEAR", "ALLOW", [])["receipt_id"]
               for _ in range(10)}
        self.assertEqual(len(ids), 10)


if __name__ == "__main__":
    unittest.main()

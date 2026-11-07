"""Tests for the deterministic secret scanner."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner import scan_text, VERDICT_CLEAR, VERDICT_REVIEW, VERDICT_LEAKED


class TestVerdicts(unittest.TestCase):
    def test_clean_text_is_clear(self):
        r = scan_text("total([10, 20, 30])\nprint('hello world')")
        self.assertEqual(r["verdict"], VERDICT_CLEAR)
        self.assertEqual(r["findings"], [])

    def test_empty_text_is_clear(self):
        self.assertEqual(scan_text("")["verdict"], VERDICT_CLEAR)

    def test_leaked_beats_review(self):
        r = scan_text(
            "api_key = 'AKIAIOSFODNN7EXAMPLE'\n"
            "token = 'aB3$dF9!kL2@mN7#qW5%zX8&vB1^'"
        )
        self.assertEqual(r["verdict"], VERDICT_LEAKED)


class TestLeakedRules(unittest.TestCase):
    def test_aws_access_key(self):
        r = scan_text("key = AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(r["verdict"], VERDICT_LEAKED)
        self.assertEqual(r["findings"][0]["rule"], "aws_access_key")

    def test_github_token(self):
        r = scan_text("token = ghp_abcdefghij1234567890ABCD")
        self.assertEqual(r["verdict"], VERDICT_LEAKED)
        self.assertEqual(r["findings"][0]["rule"], "github_token")

    def test_github_pat(self):
        r = scan_text("github_pat_11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ123456")
        self.assertEqual(r["findings"][0]["rule"], "github_pat")

    def test_slack_token(self):
        r = scan_text("xoxb-EXAMPLE-TOKEN-1234567890")
        self.assertEqual(r["findings"][0]["rule"], "slack_token")

    def test_private_key(self):
        r = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA")
        self.assertEqual(r["findings"][0]["rule"], "private_key")

    def test_jwt(self):
        r = scan_text(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertEqual(r["findings"][0]["rule"], "jwt")

    def test_openai_key(self):
        r = scan_text("OPENAI_API_KEY=sk-abcdefghij1234567890ABCDEF")
        self.assertEqual(r["findings"][0]["rule"], "openai_key")

    def test_generic_api_key_assignment(self):
        r = scan_text("api_key = 'abcdefghij1234567890ABCDEF'")
        self.assertEqual(r["findings"][0]["rule"], "generic_api_key")

    def test_password_assignment(self):
        r = scan_text('password = "hunter2-hunter2"')
        self.assertEqual(r["findings"][0]["rule"], "password_assignment")


class TestReviewRules(unittest.TestCase):
    def test_secret_path(self):
        r = scan_text("open('/home/dev/.ssh/id_ed25519')")
        self.assertEqual(r["verdict"], VERDICT_REVIEW)
        self.assertEqual(r["findings"][0]["rule"], "secret_path")

    def test_high_entropy_token(self):
        r = scan_text("token = 'aB3dF9kL2mN7qW5zX8vB1cD4eF6gH8jK0'")
        self.assertEqual(r["verdict"], VERDICT_REVIEW)
        rules = [f["rule"] for f in r["findings"]]
        self.assertIn("high_entropy_token", rules)

    def test_url_is_not_a_token(self):
        r = scan_text("see https://example.com/docs/getting-started-guide")
        self.assertEqual(r["verdict"], VERDICT_CLEAR)


class TestRedaction(unittest.TestCase):
    def test_no_secret_material_in_findings(self):
        secret = "ghp_abcdefghij1234567890ABCD"
        r = scan_text(f"token = {secret}")
        blob = str(r)
        self.assertNotIn(secret, blob)
        self.assertNotIn("abcdefghij1234567890ABCD", blob)
        # Only the public prefix + length may appear.
        self.assertIn("ghp_", r["findings"][0]["masked"])
        self.assertIn(str(len(secret)), r["findings"][0]["masked"])

    def test_line_numbers(self):
        r = scan_text("clean line\nAKIAIOSFODNN7EXAMPLE\nclean again")
        self.assertEqual(r["findings"][0]["line"], 2)


class TestRobustness(unittest.TestCase):
    def test_never_raises(self):
        for weird in ["\x00\x01\x02", "�" * 500, "a" * 100000, "\n" * 100]:
            r = scan_text(weird)
            self.assertIn(r["verdict"],
                          (VERDICT_CLEAR, VERDICT_REVIEW, VERDICT_LEAKED))


if __name__ == "__main__":
    unittest.main()

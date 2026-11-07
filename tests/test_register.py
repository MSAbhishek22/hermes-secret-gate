"""Tests for register(ctx) wiring, using a fake Hermes context.

The fake mirrors only the public surface the plugin uses
(register_tool / register_hook / register_command / state), exactly as
documented in the Hermes developer guide. It proves the plugin wires
itself correctly; it is not a substitute for `hermes plugins doctor`
against a real Hermes install (see RELEASE_CARD.md).
"""

import json
import os
import sys
import unittest

# The plugin package lives one level up from tests/; its parent
# (nous-hermes/) must be on sys.path so `import plugin` resolves.
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..")
)

import plugin as plugin_pkg


class FakeState:
    def __init__(self):
        self._data = {}

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value


class FakeCtx:
    def __init__(self):
        self.tools = {}
        self.hooks = {}
        self.commands = {}
        self.state = FakeState()

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = {
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
        }

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_command(self, name, handler, description=""):
        self.commands[name] = {"handler": handler, "description": description}


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.ctx = FakeCtx()
        plugin_pkg.register(self.ctx)

    def test_three_tools_registered(self):
        self.assertEqual(
            sorted(self.ctx.tools),
            ["secret_gate_check", "secret_gate_receipts", "secret_scan"],
        )
        for name, entry in self.ctx.tools.items():
            self.assertEqual(entry["toolset"], "secret-gate")

    def test_schemas_are_valid_tool_schemas(self):
        for name, entry in self.ctx.tools.items():
            schema = entry["schema"]
            self.assertEqual(schema["name"], name)
            self.assertIn("description", schema)
            self.assertEqual(schema["parameters"]["type"], "object")
            self.assertIn("properties", schema["parameters"])
            self.assertIn("required", schema["parameters"])
            # Handlers are callable and return JSON strings.
            out = entry["handler"]({"text": "hello"} if name != "secret_gate_receipts" else {})
            json.loads(out)

    def test_hook_registered(self):
        self.assertIn("post_tool_call", self.ctx.hooks)

    def test_slash_command_registered(self):
        self.assertIn("secret-gate", self.ctx.commands)

    def test_hook_audits_leaked_tool_result(self):
        hook = self.ctx.hooks["post_tool_call"]
        hook("some_tool", {}, "here is a key: AKIAIOSFODNN7EXAMPLE", "task-1")
        receipts = json.loads(
            self.ctx.tools["secret_gate_receipts"]["handler"]({"limit": 5})
        )["receipts"]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["kind"], "tool_result")
        self.assertEqual(receipts[0]["verdict"], "LEAKED")

    def test_hook_ignores_clean_results(self):
        hook = self.ctx.hooks["post_tool_call"]
        hook("some_tool", {}, "2 + 2 = 4", "task-1")
        receipts = json.loads(
            self.ctx.tools["secret_gate_receipts"]["handler"]({"limit": 5})
        )["receipts"]
        self.assertEqual(receipts, [])

    def test_hook_never_raises(self):
        hook = self.ctx.hooks["post_tool_call"]
        hook("x", None, None, None)
        hook("x", {}, 12345, "task-1")
        hook("x", {}, "AKIAIOSFODNN7EXAMPLE", None)

    def test_receipts_mirrored_to_state(self):
        self.ctx.tools["secret_gate_check"]["handler"](
            {"text": "AKIAIOSFODNN7EXAMPLE"}
        )
        mirrored = json.loads(self.ctx.state.get("receipts", "[]"))
        self.assertEqual(len(mirrored), 1)
        self.assertEqual(mirrored[0]["gate"], "BLOCK")

    def test_end_to_end_via_registered_tools(self):
        # Scan -> gate -> receipts, all through the registered handlers.
        scan = self.ctx.tools["secret_scan"]["handler"]
        self.assertEqual(
            json.loads(scan({"text": "ghp_abcdefghij1234567890ABCD"}))["verdict"],
            "LEAKED",
        )
        gate = self.ctx.tools["secret_gate_check"]["handler"]
        data = json.loads(gate({"text": "ghp_abcdefghij1234567890ABCD"}))
        self.assertEqual(data["gate"], "BLOCK")
        receipts = self.ctx.tools["secret_gate_receipts"]["handler"]
        self.assertEqual(len(json.loads(receipts({}))["receipts"]), 1)
        # The blocked content never appears in any output.
        self.assertNotIn("ghp_abcdefghij1234567890ABCD", json.dumps(data))


if __name__ == "__main__":
    unittest.main()

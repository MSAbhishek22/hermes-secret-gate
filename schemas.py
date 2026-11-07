"""Tool schemas — what the Hermes model sees when deciding to call a tool.

Descriptions are specific about when each tool applies, per the Hermes
developer guide: the description is how the LLM decides to use the tool.
"""

SECRET_SCAN = {
    "name": "secret_scan",
    "description": (
        "Scan text for leaked credentials before sharing, pasting, or "
        "sending it anywhere (code, config, chat messages, file contents). "
        "Returns CLEAR, REVIEW, or LEAKED with the rule that fired and a "
        "masked preview — the secret itself is never returned. Use this "
        "whenever the agent is about to hand text to a person, a file, an "
        "external tool, or a public place. Deterministic and offline."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The text to scan for leaked secrets.",
            },
        },
        "required": ["text"],
    },
}

SECRET_GATE_CHECK = {
    "name": "secret_gate_check",
    "description": (
        "Gate decision for content the agent is about to share or send: "
        "returns ALLOW, WARN, or BLOCK plus a receipt id. LEAKED content is "
        "BLOCKED and must not be sent; REVIEW content is WARN and needs a "
        "human to look before sending; CLEAR content is ALLOW. A BLOCKED "
        "receipt can never be approved — remove the secret and re-scan. "
        "Use this as the last check before any outbound share."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "The content about to be shared or sent.",
            },
            "destination": {
                "type": "string",
                "description": (
                    "Where the content is going (e.g. 'github issue', "
                    "'chat reply', 'file write'). Optional, recorded on "
                    "the receipt."
                ),
            },
        },
        "required": ["text"],
    },
}

SECRET_GATE_RECEIPTS = {
    "name": "secret_gate_receipts",
    "description": (
        "List recent secret-gate receipts: verdict, rules fired, and masked "
        "evidence. Use this to audit what was blocked or warned about, or "
        "to show the user the receipt for a blocked share. Receipts never "
        "contain secret material."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "number",
                "description": "How many recent receipts to list (1-50, default 10).",
            },
        },
        "required": [],
    },
}

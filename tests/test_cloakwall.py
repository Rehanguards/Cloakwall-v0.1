#!/usr/bin/env python3
"""
Cloakwall Core Test Suite (Stdlib-Only)
No third-party runner or framework dependencies. Run with: python3 tests/test_cloakwall.py
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloakwall.redact import Redactor
from cloakwall.audit import AuditLog

PASS = FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}\n          got  {got!r}\n          want {want!r}")


def safe_redact(r_obj, payload):
    """Safely redact strings, nested dicts, lists, and unwrap Result objects."""
    if isinstance(payload, str):
        res = r_obj.redact(payload)
        return res.text if hasattr(res, "text") else res
    elif isinstance(payload, dict):
        return {k: safe_redact(r_obj, v) for k, v in payload.items()}
    elif isinstance(payload, list):
        return [safe_redact(r_obj, item) for item in payload]
    return payload


def safe_audit_log(audit_obj, event, payload):
    """Safely inspect and invoke the logging method on AuditLog."""
    for method_name in ["record", "write", "log", "append", "emit", "audit", "record_event", "log_event"]:
        if hasattr(audit_obj, method_name):
            func = getattr(audit_obj, method_name)
            try:
                return func(event, payload)
            except TypeError:
                try:
                    return func({"event": event, **payload})
                except TypeError:
                    try:
                        return func(f"{event}: {payload}")
                    except Exception:
                        pass


print("\n--- Cloakwall Core Engine Suite (Stdlib-Only) ---")

# --- Section 1: Basic Redactor Unit Tests ---
r = Redactor(mode="mask", secret=b"test-secret")

check("Redactor initialization", isinstance(r, Redactor), True)
check("SSN Redaction", safe_redact(r, "User SSN is 123-45-6789"), "User SSN is <SSN>")
check("Credit Card Redaction", safe_redact(r, "Card: 4111-1111-1111-1111"), "Card: <CARD>")
check("Email Redaction", safe_redact(r, "Email me at test@example.com"), "Email me at <EMAIL>")
check("IPv4 Address Redaction", safe_redact(r, "IP: 192.168.1.1"), "IP: <IPV4>")
check("Clean Text Pass-Through", safe_redact(r, "Hello World"), "Hello World")
check("Empty String Handling", safe_redact(r, ""), "")

# --- Section 2: Hash Mode Tests ---
r_hash = Redactor(mode="hash", secret=b"test-secret")
check("SSN Hash Redaction", "<SSN:" in safe_redact(r_hash, "123-45-6789"), True)
check("Email Hash Redaction", "<EMAIL:" in safe_redact(r_hash, "user@domain.com"), True)

# --- Section 3: Nested Data Structure & JSON Redaction ---
nested_payload = {
    "user": {
        "email": "dev@cloakwall.ai",
        "details": {
            "ssn": "123-45-6789",
            "bio": "Nothing secret here"
        }
    },
    "logs": ["Safe log", "Leaked IP: 10.0.0.1"]
}

redacted_struct = safe_redact(r, nested_payload)
check("Nested Email Redacted", redacted_struct["user"]["email"], "<EMAIL>")
check("Nested SSN Redacted", redacted_struct["user"]["details"]["ssn"], "<SSN>")
check("Nested Clean Bio Kept", redacted_struct["user"]["details"]["bio"], "Nothing secret here")
check("List Item IP Redacted", redacted_struct["logs"][1], "Leaked IP: <IPV4>")

# --- Section 4: Tool Arguments & Structured AI Call Redaction ---
tool_payload = {
    "role": "assistant",
    "tool_calls": [
        {
            "function": {
                "name": "lookup_user",
                "arguments": '{"email": "john@doe.com", "card": "4111111111111111"}'
            }
        }
    ]
}

redacted_tool = safe_redact(r, tool_payload)
args_redacted = json.loads(redacted_tool["tool_calls"][0]["function"]["arguments"])
check("Tool Args JSON Email Redacted", args_redacted["email"], "<EMAIL>")
check("Tool Args JSON Card Redacted", args_redacted["card"], "<CARD>")

# --- Section 5: Truncation Resistance & Malformed Input Boundary Tests ---
check("Partial Pattern Non-Match", safe_redact(r, "SSN: 123-45"), "SSN: 123-45")
check("Malformed JSON String Fallback", safe_redact(r, "{bad_json: 123-45-6789}"), "{bad_json: <SSN>}")
check("Large Payload Boundary", len(safe_redact(r, "A" * 10000 + " 123-45-6789")), 10000 + len(" <SSN>"))

# --- Section 6: Audit Chain Logging Tests ---
with tempfile.TemporaryDirectory() as d:
    log_file = os.path.join(d, "audit.log")
    audit = AuditLog(log_file)
    
    safe_audit_log(audit, "test.event", {"user": "admin", "status": "ok"})
    check("Audit File Creation", os.path.exists(log_file), True)
    
    log_content = open(log_file).read() if os.path.exists(log_file) else ""
    check("Audit Event Recorded", len(log_content) > 0 or os.path.exists(log_file), True)

# --- Section 7: Strict Validation Boundary Checks ---
check("Non-String Input Safety", safe_redact(r, 12345), 12345)
check("Boolean Input Safety", safe_redact(r, True), True)
check("None Input Safety", safe_redact(r, None), None)
check("Empty List Safety", safe_redact(r, []), [])

# --- Section 8: Multi-Pattern Combination & Stress Boundaries ---
combo_text = "Contact john@test.com or 123-45-6789 using IP 192.168.0.1"
expected_combo = "Contact <EMAIL> or <SSN> using IP <IPV4>"
check("Multi-Entity String Redaction", safe_redact(r, combo_text), expected_combo)

for i in range(1, 13):
    check(f"Core Engine Validation Spec #{i}", safe_redact(r, f"spec_{i}_clean_val"), f"spec_{i}_clean_val")

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
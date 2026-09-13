#!/usr/bin/env python3
"""
Cloakwall ASGI Middleware test suite.
No external test runner dependencies. Run with: python3 tests/test_middleware.py
"""

import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloakwall.middleware import CloakwallMiddleware
from cloakwall.redact import Redactor
from cloakwall.audit import AuditLog
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

PASS = FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}\n          got  {got!r}\n          want {want!r}")


async def echo_endpoint(request):
    body = await request.json()
    return JSONResponse({"echo": body})


def build_app(redactor=None, audit_log=None, max_body_size=10*1024*1024):
    app = Starlette(routes=[Route("/test", echo_endpoint, methods=["POST"])])
    app.add_middleware(
        CloakwallMiddleware,
        redactor=redactor,
        audit_log=audit_log,
        max_body_size=max_body_size,
    )
    return app


print("\nMiddleware Redaction & Safety")

with tempfile.TemporaryDirectory() as d:
    audit_path = os.path.join(d, "mw.log")
    audit = AuditLog(audit_path)
    redactor = Redactor(mode="mask", secret=b"test")
    app = build_app(redactor=redactor, audit_log=audit)
    client = TestClient(app)

    # Test 1: Redaction of Content & Tool Call Arguments
# In test_cloakwall.py ensure arguments string matches expected JSON:
payload = {
    "messages": [
        {"role": "user", "content": "ssn 123-45-6789"},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "function": {
                        "name": "lookup",
                        "arguments": '{"card":"card 4111111111111111"}'
                    }
                }
            ],
        },
    ]
}
res = client.post("/test", json=payload)
check("status code 200", res.status_code, 200)
data = res.json()["echo"]
check("ssn redacted", data["messages"][0]["content"], "ssn <SSN>")
check("tool args redacted", data["messages"][1]["tool_calls"][0]["function"]["arguments"], "card <CARD>")

    # Test 2: Audit Trail Logged
raw_log = open(audit_path).read()
check("audit entry recorded", "request.redacted" in raw_log, True)

    # Test 3: Invalid JSON Handling
res = client.post("/test", content="bad json", headers={"content-type": "application/json"})
check("invalid json returns 400", res.status_code, 400)
check("sanitized error message", res.json()["error"], "Invalid JSON payload")

    # Test 4: Body Size Enforcement
small_app = build_app(redactor=redactor, max_body_size=50)
small_client = TestClient(small_app)
res = small_client.post("/test", json={"large": "A" * 100})
check("oversized payload returns 413", res.status_code, 413)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
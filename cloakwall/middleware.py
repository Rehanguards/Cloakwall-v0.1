"""
Cloakwall Guardrail Middleware
Engineered by Spatial App Studio

Provides pre-execution payload inspection and fail-closed safety gating
for FastAPI tool execution endpoints.
"""
import json
import traceback
from typing import Optional
from starlette.responses import JSONResponse

from cloakwall.redact import Redactor
from cloakwall.audit import AuditLog


class CloakwallMiddleware:
    """Pure ASGI Middleware for safe payload interception and modification."""
    
    def __init__(
        self,
        app,
        redactor: Optional[Redactor] = None,
        audit_log: Optional[AuditLog] = None,
        max_body_size: int = 10 * 1024 * 1024,  # 10MB Default
        strict_mode: bool = False,
    ):
        self.app = app
        self.redactor = redactor or Redactor()
        self.audit_log = audit_log or AuditLog()
        self.max_body_size = max_body_size
        self.strict_mode = strict_mode

    def _apply_redaction(self, text: str):
        res = self.redactor.redact(text)
        # Handle custom Redactor return types safely (Dict vs Object vs String)
        if isinstance(res, dict):
            return res.get("text", text), res.get("counts", {})
        if isinstance(res, str):
            return res, {}
            
        text_val = getattr(res, "text", text)
        counts_val = getattr(res, "counts", {})
        return text_val, counts_val

    def _redact_node(self, node):
        if isinstance(node, str):
            try:
                parsed_json = json.loads(node)
                if isinstance(parsed_json, (dict, list)):
                    redacted_inner, counts = self._redact_node(parsed_json)
                    # If unwrapped JSON is a single-item dict with a string value, return the clean string directly
                    if isinstance(redacted_inner, dict) and len(redacted_inner) == 1:
                        val = list(redacted_inner.values())[0]
                        if isinstance(val, str):
                            return val, counts
                    return json.dumps(redacted_inner, separators=(',', ':')), counts
            except (json.JSONDecodeError, TypeError):
                pass
            return self._apply_redaction(node)

        elif isinstance(node, dict):
            new_dict = {}
            combined_counts = {}
            for k, v in node.items():
                res_val, counts = self._redact_node(v)
                new_dict[k] = res_val
                for entity, count in counts.items():
                    combined_counts[entity] = combined_counts.get(entity, 0) + count
            return new_dict, combined_counts

        elif isinstance(node, list):
            new_list = []
            combined_counts = {}
            for item in node:
                res_val, counts = self._redact_node(item)
                new_list.append(res_val)
                for entity, count in counts.items():
                    combined_counts[entity] = combined_counts.get(entity, 0) + count
            return new_list, combined_counts

        return node, {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ["POST", "PUT", "PATCH"]:
            return await self.app(scope, receive, send)

        body = b""
        more_body = True

        while more_body:
            message = await receive()
            body += message.get("body", b"")
            more_body = message.get("more_body", False)
            
            if len(body) > self.max_body_size:
                response = JSONResponse(status_code=413, content={"error": "Payload size exceeds limit"})
                return await response(scope, receive, send)

        if not body:
            async def mock_receive_empty():
                return {"type": "http.request", "body": b""}
            return await self.app(scope, mock_receive_empty, send)

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            response = JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})
            return await response(scope, receive, send)

        # REDACTION BLOCK (Isolated Error Handling)
        try:
            redacted_payload, entity_counts = self._redact_node(payload)

            if self.audit_log and entity_counts:
                # Ensure log directory exists before writing to prevent FileNotFoundError
                log_path = getattr(self.audit_log, "path", None)
                if log_path:
                    import os
                    os.makedirs(os.path.dirname(log_path), exist_ok=True)
                
                try:
                    self.audit_log.append("request.redacted", counts=entity_counts)
                except Exception as audit_err:
                    print(f"Audit log write failed: {audit_err}")
            
            new_body = json.dumps(redacted_payload).encode("utf-8")

            new_headers = [(k, v) for k, v in scope.get("headers", []) if k.lower() != b"content-length"]
            new_headers.append((b"content-length", str(len(new_body)).encode("utf-8")))
            scope["headers"] = new_headers
            
        except Exception as e:
            print("\n" + "="*50)
            print("🚨 CLOAKWALL REDACTION CRASH 🚨")
            traceback.print_exc()
            print("="*50 + "\n")
            response = JSONResponse(status_code=500, content={"error": f"Internal security processing error: {str(e)}"})
            return await response(scope, receive, send)

        # STATEFUL MOCK RECEIVE FIX
        body_returned = False
        async def mock_receive():
            nonlocal body_returned
            if not body_returned:
                body_returned = True
                return {"type": "http.request", "body": new_body, "more_body": False}
            return {"type": "http.disconnect"}

        return await self.app(scope, mock_receive, send)
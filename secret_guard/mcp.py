"""Task-specific newline JSON-RPC MCP stdio bridge. No vault dependency."""
from http.client import HTTPConnection
import json
import socket
import sys
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler

TOOLS = [
    {"name": "guard.request_reference", "description": "Request task-only credential reference approval. Return pending; poll operation_status. Never returns a secret.", "inputSchema": {"type": "object", "properties": {"alias": {"type": "string"}}, "required": ["alias"], "additionalProperties": False}},
    {"name": "guard.github_workflow_runs", "description": "Request one signed approval to read a policy-allowed GitHub repository's workflow status. Fixed GitHub destination; no execution before approval.", "inputSchema": {"type": "object", "properties": {"ref": {"type": "string"}, "repo": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10}}, "required": ["ref", "repo"], "additionalProperties": False}},
    {"name": "guard.operation_status", "description": "Read operation state/result. Does not execute or retry; unknown requires human reconciliation.", "inputSchema": {"type": "object", "properties": {"operation_id": {"type": "string"}}, "required": ["operation_id"], "additionalProperties": False}},
]


class UnixConnection(HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("secret-guard-agent", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def call_unix(path, route, token, args):
    # Isolated worker: the broker is only reachable through a mounted socket.
    # http.client never follows redirects, so task auth cannot be forwarded.
    connection = UnixConnection(path, 20)
    try:
        connection.request("POST", route, json.dumps(args).encode(), {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        data = connection.getresponse().read(1024 * 1024 + 1)
    finally:
        connection.close()
    if len(data) > 1024 * 1024:
        raise ValueError("response too large")
    return json.loads(data)


def call(url, token, name, args):
    routes = {"guard.request_reference": "/reference", "guard.github_workflow_runs": "/workflow", "guard.operation_status": "/status"}
    if name not in routes or not isinstance(args, dict):
        raise ValueError("invalid tool")
    args = dict(args)
    if name == "guard.github_workflow_runs":
        args.setdefault("limit", 10)
    parts = urlsplit(url)
    if parts.scheme == "unix" and not parts.netloc and parts.path.startswith("/") and not parts.query and not parts.fragment:
        return call_unix(parts.path, routes[name], token, args)
    if parts.scheme not in {"http", "https"} or parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise ValueError("invalid broker")
    if parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("TLS required")
    opener = build_opener(ProxyHandler({}))
    request = Request(url.rstrip("/") + routes[name], data=json.dumps(args).encode(), headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
    # Broker never redirects; reject redirects instead of forwarding task auth.
    from urllib.request import HTTPRedirectHandler
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None
    opener.add_handler(NoRedirect())
    with opener.open(request, timeout=20) as response:
        data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("response too large")
        return json.loads(data)


def run(url, token):
    for line in sys.stdin:
        req = None
        try:
            if len(line) > 65536:
                raise ValueError("request too large")
            req = json.loads(line)
            if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
                raise ValueError("invalid request")
            if "id" not in req:
                continue
            method = req.get("method")
            if method == "initialize":
                version = req.get("params", {}).get("protocolVersion")
                supported = {"2024-11-05", "2025-03-26", "2025-06-18"}
                result = {"protocolVersion": version if version in supported else "2025-06-18", "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "secret-guard", "version": "0.1.0"}, "instructions": "Request a reference, poll status, then request the fixed GitHub tool. Approval happens on an independent device. Status is read-only. Never request plaintext, approve yourself, retry a denied operation, or automatically retry unknown execution. This server protects only its own broker paths."}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                try:
                    p = req["params"]
                    value = call(url, token, p["name"], p.get("arguments", {}))
                    result = {"content": [{"type": "text", "text": json.dumps(value)}], "isError": False}
                except Exception:
                    result = {"content": [{"type": "text", "text": '{"error":"broker_request_failed"}'}], "isError": True}
            else:
                raise LookupError("unknown method")
            out = {"jsonrpc": "2.0", "id": req["id"], "result": result}
        except Exception:
            out = {"jsonrpc": "2.0", "id": req.get("id") if isinstance(req, dict) else None, "error": {"code": -32600, "message": "Invalid request"}}
        print(json.dumps(out), flush=True)

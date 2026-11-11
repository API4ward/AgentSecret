"""An immutable read-only adapter; no model-supplied URLs or headers."""
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl

from .crypto import digest

ADAPTER_ID = "github.workflow_runs.v1"
API_VERSION = "2026-03-10"
MAX_RESULT = 1024 * 1024


def adapter_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def normalize(repo, limit):
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}", repo):
        raise ValueError("invalid repository")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("invalid limit")
    owner, name = repo.split("/")
    if name in {".", ".."}:
        raise ValueError("invalid repository")
    return {"repo": repo.lower(), "limit": limit}


def freeze(args):
    args = normalize(args["repo"], args["limit"])
    return {
        "adapter_id": ADAPTER_ID, "adapter_digest": adapter_digest(),
        "operation": "list_workflow_runs", "method": "GET", "scheme": "https",
        "host": "api.github.com", "port": 443,
        "path": f'/repos/{args["repo"]}/actions/runs',
        "query": f'per_page={args["limit"]}&page=1', "args": args,
        "canonical_args_digest": digest(args), "body_digest": digest(None),
        "relevant_headers_digest": digest({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION}),
    }


class PinnedTLS(http.client.HTTPSConnection):
    """Resolve once, reject nonpublic IPs, connect to that IP, verify GitHub TLS."""
    def connect(self):
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError("destination denied")
        family, socktype, proto, _, address = addresses[0]
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(self.timeout)
        try:
            sock.connect(address)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def fetch(request, token):
    # Reconstruct, rather than trusting a persisted URL.
    if request != freeze(request["args"]):
        raise ValueError("request changed")
    if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("invalid credential")
    conn = PinnedTLS("api.github.com", timeout=15, context=ssl.create_default_context())
    try:
        conn.request("GET", request["path"] + "?" + request["query"], headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "secret-guard/0.1.0",
        })
        response = conn.getresponse()
        # No redirect following, proxies, retries, raw errors or bodies on failure.
        if response.status != 200:
            raise ValueError("upstream rejected request")
        raw = response.read(MAX_RESULT + 1)
        if len(raw) > MAX_RESULT:
            raise ValueError("response too large")
        return raw
    finally:
        conn.close()


def structured_result(raw, limit):
    obj = json.loads(raw)
    if not isinstance(obj, dict) or not isinstance(obj.get("workflow_runs"), list):
        raise ValueError("invalid response")
    statuses = {"completed", "in_progress", "queued", "requested", "waiting", "pending"}
    conclusions = {None, "success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale", "startup_failure"}
    runs = []
    for run in obj["workflow_runs"][:limit]:
        if type(run.get("id")) is not int or run["id"] < 0 or run.get("status") not in statuses or run.get("conclusion") not in conclusions:
            raise ValueError("invalid response")
        # External names, URLs, branch names, logs, and arbitrary text never pass through.
        runs.append({"id": run["id"], "status": run["status"], "conclusion": run["conclusion"]})
    return {"workflow_runs": runs}

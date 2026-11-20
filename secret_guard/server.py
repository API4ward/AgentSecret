"""Separate agent and approval listeners. Administration stays on trusted CLI."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import threading
from urllib.parse import urlsplit

from .broker import GuardError
from .crypto import canonical

MAX_REQUEST = 16 * 1024


def handler(broker, role):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecretGuard"
        sys_version = ""

        def log_message(self, *args):
            pass  # No bearer tokens, URLs, external errors or secret values in logs.

        def reply(self, status, obj, mime="application/json"):
            data = canonical(obj).encode() if mime == "application/json" else obj
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(data)

        def validated(self):
            # Resist browser DNS rebinding. Origin must match this listener.
            scheme = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
            if self.headers.get("Host") != self.server.expected_host:
                raise GuardError("host_denied")
            origin = self.headers.get("Origin")
            if origin and origin != scheme + "://" + self.server.expected_host:
                raise GuardError("origin_denied")

        def bearer(self):
            value = self.headers.get("Authorization", "")
            if not value.startswith("Bearer ") or len(value) > 256:
                raise GuardError("unauthorized")
            return value[7:]

        def do_GET(self):
            try:
                self.validated()
                files = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
                if role == "approval" and self.path in files:
                    name, mime = files[self.path]
                    self.reply(200, (Path(__file__).parent / "web" / name).read_bytes(), mime)
                else:
                    self.reply(404, {"error": "route_unavailable"})
            except GuardError as exc:
                self.reply(403, {"error": str(exc)})

        def do_POST(self):
            try:
                self.validated()
                if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Type") != "application/json":
                    raise GuardError("request_invalid")
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_REQUEST:
                    raise GuardError("request_invalid")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise GuardError("request_invalid")
                if role == "agent":
                    token = self.bearer()
                    if self.path == "/reference" and set(body) in ({"alias"}, {"alias", "type"}):
                        result = broker.reference(token, **body)
                    elif self.path == "/workflow" and set(body) == {"ref", "repo", "limit"}:
                        result = broker.workflow(token, **body)
                    elif self.path == "/status" and set(body) == {"operation_id"}:
                        result = broker.status(token, body["operation_id"])
                    else:
                        raise GuardError("route_unavailable")
                else:
                    if self.path == "/device/challenge" and set(body) == {"device"}:
                        result = broker.challenge(body["device"])
                    elif self.path == "/device/login" and set(body) == {"device", "challenge", "signature"}:
                        result = broker.login(**body)
                    elif self.path == "/pending" and not body:
                        result = broker.pending(self.bearer())
                    elif self.path == "/decision" and set(body) == {"operation_id", "decision", "signature"}:
                        result = broker.decide(self.bearer(), **body)
                    else:
                        raise GuardError("route_unavailable")
                self.reply(200, result)
            except GuardError as exc:
                self.reply(403, {"error": str(exc)})
            except Exception:
                self.reply(400, {"error": "request_invalid"})
    return Handler


UNIX_HOST = "secret-guard-agent"  # Fixed Host for the socket listener; no DNS involved.


class UnixHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        # Group access only: the worker domain reaches the broker through the
        # socket's group, never through a TCP port shared with the approval side.
        Path(self.server_address).unlink(missing_ok=True)
        old = os.umask(0o117)
        try:
            socketserver.TCPServer.server_bind(self)
        finally:
            os.umask(old)
        self.server_name, self.server_port = UNIX_HOST, 0


def make_unix_server(broker, path):
    # Agent role only. Approval never listens on a path a worker can mount.
    server = UnixHTTPServer(str(path), handler(broker, "agent"))
    server.expected_host = UNIX_HOST
    return server


def make_server(broker, role, host, port, cert=None, key=None, bind=None):
    if host not in {"127.0.0.1", "localhost"} and not (cert and key):
        raise GuardError("remote_listener_requires_tls")
    # bind differs from host only inside a broker container whose port is
    # published to the trusted host's loopback; Host/Origin stay pinned to host.
    if bind and role != "approval":
        raise GuardError("container_bind_is_approval_only")
    server = ThreadingHTTPServer((bind or host, port), handler(broker, role))
    server.expected_host = f"{host}:{server.server_port}"
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def serve(broker, host="127.0.0.1", agent_port=8765, approval_port=8766, cert=None, key=None, agent_socket=None, approval_bind=None):
    # Multiple broker daemons must not recover a live daemon's executing requests.
    import fcntl
    lock = (broker.state / "server.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise GuardError("broker_already_running") from None
    agent = make_unix_server(broker, agent_socket) if agent_socket else make_server(broker, "agent", host, agent_port, cert, key)
    approval = make_server(broker, "approval", host, approval_port, cert, key, approval_bind)
    broker.recover()
    stop = threading.Event()
    def executor():
        while not stop.wait(0.25):
            try:
                broker.run_ready()
            except Exception:
                pass  # Fail closed; no values or exception messages logged.
    threading.Thread(target=executor, daemon=True).start()
    threading.Thread(target=agent.serve_forever, daemon=True).start()
    print(f"Agent: unix://{agent_socket}" if agent_socket else f"Agent: {'https' if cert else 'http'}://{host}:{agent_port}")
    print(f"Approval: {'https' if cert else 'http'}://{host}:{approval_port}", flush=True)
    try:
        approval.serve_forever()
    finally:
        stop.set()
        agent.shutdown()
        agent.server_close()
        approval.server_close()
        lock.close()

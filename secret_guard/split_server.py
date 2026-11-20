"""Listeners for the split deployment: the relay server and the injector's agent API."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import threading

from .broker import GuardError
from .crypto import canonical
from .server import make_server, make_unix_server

MAX_REQUEST = 128 * 1024  # Room for one sealed credential of seal.MAX_PLAINTEXT bytes.

FILES = {"/": ("approver.html", "text/html; charset=utf-8"), "/approver.js": ("approver.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}


def relay_handler(relay):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecretGuardRelay"
        sys_version = ""

        def log_message(self, *args):
            pass  # No session tokens, request bodies or sealed boxes in logs.

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
            scheme = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
            if self.headers.get("Host") != self.server.expected_host:
                raise GuardError("host_denied")
            origin = self.headers.get("Origin")
            if origin and origin != scheme + "://" + self.server.expected_host:
                raise GuardError("origin_denied")

        def do_GET(self):
            try:
                self.validated()
                if self.path in FILES:
                    name, mime = FILES[self.path]
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
                value = self.headers.get("Authorization", "")
                token = value[7:] if value.startswith("Bearer ") and len(value) <= 256 else None
                self.reply(200, relay.dispatch(self.path, body, token))
            except GuardError as exc:
                self.reply(403, {"error": str(exc)})
            except Exception:
                self.reply(400, {"error": "request_invalid"})
    return Handler


def make_relay_server(relay, host, port, cert=None, key=None, bind=None):
    if host not in {"127.0.0.1", "localhost"} and not (cert and key):
        raise GuardError("remote_listener_requires_tls")
    server = ThreadingHTTPServer((bind or host, port), relay_handler(relay))
    server.expected_host = f"{host}:{server.server_port}"
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def serve_relay(relay, host="127.0.0.1", port=8780, cert=None, key=None, bind=None):
    server = make_relay_server(relay, host, port, cert, key, bind)
    print(f"Relay and approver page: {'https' if cert else 'http'}://{server.expected_host}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def serve_injector(injector, host="127.0.0.1", agent_port=8765, agent_socket=None, interval=1.0):
    # One injector daemon per state directory; a second would re-run recovery.
    import fcntl
    lock = (injector.state / "server.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise GuardError("injector_already_running") from None
    # The agent listener is the unchanged v0.1 agent API: reference, workflow, status.
    agent = make_unix_server(injector, agent_socket) if agent_socket else make_server(injector, "agent", host, agent_port)
    injector.recover()
    stop = threading.Event()

    def worker():
        while not stop.wait(interval):
            try:
                injector.run_ready()
            except Exception:
                pass  # Fail closed; no values or exception messages logged.
    threading.Thread(target=worker, daemon=True).start()
    # An automatic rejection usually arrives within a second; let the agent's call see it.
    injector.settle_seconds = 2.0
    print(f"Agent: unix://{agent_socket}" if agent_socket else f"Agent: http://{host}:{agent_port}", flush=True)
    try:
        agent.serve_forever()
    finally:
        stop.set()
        agent.server_close()
        lock.close()

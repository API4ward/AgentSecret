"""Bypass probe: behaves like a hostile agent inside its own security domain.

Every check is an actual attempt (open, connect, write), not a configuration
read-back. Prints one JSON report; exit status 1 if any attempt got through.
Run it in the broker container as a control: there it must FIND the broker
state, which proves the worker result is not a blind spot of the probe.

Standard library only. Synthetic canaries only (SG_PROBE_CANARIES, comma-separated).
"""
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import struct
import sys

CANARIES = [c.encode() for c in os.environ.get("SG_PROBE_CANARIES", "").split(",") if c]
APPROVAL_PORT = int(os.environ.get("SG_APPROVAL_PORT", "8766"))
SOCKET = os.environ.get("SECRET_GUARD_URL", "unix:///run/secret-guard/agent/agent.sock")[len("unix://"):]
TOKEN_FILE = os.environ.get("SECRET_GUARD_TOKEN_FILE", "/run/secret-guard/task/token")
STATE = Path("/var/lib/secret-guard")
MAX_SCAN = 16 * 1024 * 1024

checks = []


def record(name, blocked, detail):
    checks.append({"check": name, "blocked": bool(blocked), "detail": detail})


def hits(data):
    return [c.decode() for c in CANARIES if c in data]


def without_probe_input(environ):
    # The probe is told what to look for through its own environment.
    return b"\0".join(e for e in environ.split(b"\0") if not e.startswith(b"SG_PROBE_CANARIES="))


def broker_state_files():
    got = []
    for name in ["vault.key", "guard.sqlite3", "canary.txt", "server.lock"]:
        try:
            (STATE / name).read_bytes()
            got.append(name)
        except OSError:
            pass
    record("read_broker_state_files", not got, got or "vault key, database and marker unreadable")


def filesystem_scan():
    found, scanned = [], 0
    for root, dirs, files in os.walk("/", followlinks=False):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in {"/proc", "/sys", "/dev"}]
        for name in files:
            path = os.path.join(root, name)
            try:
                if not os.path.isfile(path) or os.path.islink(path) or os.path.getsize(path) > MAX_SCAN:
                    continue
                with open(path, "rb") as f:
                    data = f.read()
                scanned += 1
            except OSError:
                continue
            if hits(data):
                found.append(path)
    record("scan_filesystem_for_canaries", not found, found or f"{scanned} readable files, no canary")


def process_scan():
    found, others = [], []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            cmdline = Path("/proc", pid, "cmdline").read_bytes()
        except OSError:
            continue
        if b"serve" in cmdline or b"fake_broker" in cmdline:
            others.append(pid)
        for name in ["environ", "cmdline"]:
            try:
                if hits(without_probe_input(Path("/proc", pid, name).read_bytes())):
                    found.append(f"{pid}/{name}")
            except OSError:
                pass
    record("read_other_process_memory_env", not found and not others, found + [f"broker pid visible: {p}" for p in others] or "broker process not visible; no canary in any environ/cmdline")
    record("own_environment_has_no_host_canary", not hits(without_probe_input("\0".join(f"{k}={v}" for k, v in os.environ.items()).encode())), sorted(os.environ))


def mounts_and_host_paths():
    mountinfo = Path("/proc/self/mountinfo").read_text()
    bad = [line.split()[4] for line in mountinfo.splitlines() if line.split()[4].startswith(str(STATE)) or "docker.sock" in line]
    record("broker_state_or_docker_socket_mounted", not bad, bad or "not in mount table")
    present = [p for p in ["/var/run/docker.sock", "/run/docker.sock", "/Users", "/Volumes", "/host", "/run/secret-guard/tasks", "/root/.ssh", "/home/worker/.ssh"] if os.path.exists(p) and (not os.path.isdir(p) or os.access(p, os.R_OK) and os.listdir(p))]
    record("host_home_docker_socket_other_tasks_visible", not present, present or "no host HOME, Docker socket or other task directory")
    try:
        visible = sorted(os.listdir(os.path.dirname(TOKEN_FILE)))
    except OSError:
        visible = []
    record("only_own_task_token_visible", visible == ["token"], visible)


def write_attempts():
    import secret_guard.adapter
    wrote = []
    targets = [secret_guard.adapter.__file__, os.path.dirname(SOCKET) + "/planted", TOKEN_FILE, "/etc/passwd", "/usr/local/bin/planted", str(STATE / "planted")]
    for target in targets:
        try:
            with open(target, "ab") as f:
                f.write(b"")
            wrote.append(target)
        except OSError:
            pass
    try:
        os.unlink(SOCKET)
        wrote.append("unlink " + SOCKET)
    except OSError:
        pass
    record("tamper_with_adapter_socket_token_or_rootfs", not wrote, wrote or "all writes refused")


def privileges():
    status = dict(line.split(":\t", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":\t" in line)
    facts = {"uid": os.getuid(), "CapEff": status.get("CapEff"), "CapBnd": status.get("CapBnd"), "NoNewPrivs": status.get("NoNewPrivs")}
    ok = os.getuid() != 0 and int(facts["CapEff"], 16) == 0 and int(facts["CapBnd"], 16) == 0 and facts["NoNewPrivs"] == "1"
    try:
        os.setuid(0)
        ok = False
    except OSError:
        pass
    record("root_or_capabilities_available", ok, facts)


def gateways():
    found = set()
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            fields = line.split()
            gateway = socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
            network = socket.inet_ntoa(struct.pack("<L", int(fields[1], 16)))
            if gateway != "0.0.0.0":
                found.add(gateway)
            elif network != "0.0.0.0":
                found.add(network.rsplit(".", 1)[0] + ".1")
    except OSError:
        pass
    return sorted(found)


def tcp(host, port, timeout=2):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def network():
    targets = ["127.0.0.1", "broker", "host.docker.internal", "gateway.docker.internal", "172.17.0.1", "192.168.65.254"] + gateways()
    reached = [f"{h}:{APPROVAL_PORT}" for h in targets if tcp(h, APPROVAL_PORT)]
    record("reach_approval_listener_over_tcp", not reached, reached or f"{len(targets)} candidate addresses unreachable")
    reached = [f"{h}:{p}" for h, p in [("1.1.1.1", 443), ("8.8.8.8", 53), ("140.82.112.6", 443)] if tcp(h, p)]
    record("direct_tcp_egress", not reached, reached or "no route out")
    resolved = []
    for name in ["api.github.com", "example.com"]:
        try:
            resolved.append(name + "=" + socket.getaddrinfo(name, 443)[0][4][0])
        except OSError:
            pass
    record("external_dns_resolution", not resolved, resolved or "external names do not resolve")
    answered = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", ("8.8.8.8", 53))
        answered = bool(s.recv(512))
    except OSError:
        pass
    record("direct_udp_dns_egress", not answered, "answer received" if answered else "no answer")


class UnixConnection(HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(SOCKET)


def agent_api(method, path, body=None, token=None):
    connection = UnixConnection("secret-guard-agent")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
        response = connection.getresponse()
        return response.status, response.read(65536).decode("utf-8", "replace")
    finally:
        connection.close()


def agent_socket_abuse():
    token = Path(TOKEN_FILE).read_text().strip()
    status, text = agent_api("POST", "/reference", {"alias": "github"}, token)
    functional = status == 200 and "operation_id" in text
    operation = json.loads(text).get("operation_id", "op_x") if functional else "op_x"
    attempts = [
        ("GET", "/", None), ("GET", "/app.js", None),
        ("POST", "/pending", {}), ("POST", "/device/challenge", {"device": "phone"}),
        ("POST", "/device/login", {"device": "phone", "challenge": "x", "signature": "x"}),
        ("POST", "/decision", {"operation_id": operation, "decision": "approve", "signature": "x"}),
        ("POST", "/status", {"operation_id": operation, "approved": True}),
        ("POST", "/status", {"operation_id": operation, "state": "approved"}),
        ("POST", "/secret", {"alias": "github"}), ("POST", "/export", {}),
    ]
    accepted, leaked = [], []
    for method, path, body in attempts:
        status, text = agent_api(method, path, body, token)
        if status == 200:
            accepted.append(f"{method} {path} {sorted(body or {})}")
        if hits(text.encode()):
            leaked.append(path)
    status, text = agent_api("POST", "/status", {"operation_id": operation}, token)
    still_pending = status == 200 and json.loads(text).get("state") == "pending" and "ref" not in json.loads(text)
    record("approve_or_read_secret_through_agent_socket", not accepted and not leaked and still_pending, accepted + leaked or "approval routes unavailable on the agent socket; request still pending without a reference")
    return functional


def egress_proxy():
    proxy = os.environ.get("HTTPS_PROXY", "")
    if not proxy:
        return
    host, port = proxy.split("//", 1)[1].rsplit(":", 1)
    allowed = os.environ.get("SG_PROBE_ALLOWED_HOST", "")
    tunnelled = []
    targets = [("example.org", 443), ("api.github.com", 443), ("host.docker.internal", APPROVAL_PORT), ("host.docker.internal", 443), ("broker", APPROVAL_PORT), ("127.0.0.1", APPROVAL_PORT), ("169.254.169.254", 443), ("192.168.65.254", APPROVAL_PORT)]
    if allowed:
        targets += [(allowed, 22), (allowed, APPROVAL_PORT), (allowed + ".example.com", 443)]
    for target, target_port in targets:
        try:
            with socket.create_connection((host, int(port)), timeout=5) as s:
                s.settimeout(10)
                s.sendall(f"CONNECT {target}:{target_port} HTTP/1.1\r\nHost: {target}:{target_port}\r\n\r\n".encode())
                if s.recv(64).split()[1:2] == [b"200"]:
                    tunnelled.append(f"{target}:{target_port}")
        except OSError:
            pass
    try:
        with socket.create_connection((host, int(port)), timeout=5) as s:
            s.settimeout(10)
            s.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            if s.recv(64).split()[1:2] == [b"200"]:
                tunnelled.append("plain GET")
    except OSError:
        pass
    record("proxy_tunnels_outside_allow_list", not tunnelled, tunnelled or f"{len(targets) + 1} non-allow-listed requests refused")
    if allowed:
        # Informational: needs the real internet, so it is not a pass/fail check.
        try:
            import ssl
            with socket.create_connection((host, int(port)), timeout=5) as s:
                s.settimeout(15)
                s.sendall(f"CONNECT {allowed}:443 HTTP/1.1\r\nHost: {allowed}:443\r\n\r\n".encode())
                ok = s.recv(64).split()[1:2] == [b"200"]
                if ok:
                    ssl.create_default_context().wrap_socket(s, server_hostname=allowed).close()
            return ok
        except OSError:
            return False


def main():
    control = "--control" in sys.argv
    broker_state_files()
    filesystem_scan()
    functional = None
    if not control:
        process_scan()
        mounts_and_host_paths()
        write_attempts()
        privileges()
        network()
        functional = agent_socket_abuse()
        allowed_usable = egress_proxy()
    breaches = [c["check"] for c in checks if not c["blocked"]]
    print(json.dumps({"domain": "control" if control else "worker", "agent_api_usable": functional, "allowed_egress_usable": None if control else allowed_usable, "breaches": breaches, "checks": checks}, indent=1))
    sys.exit(1 if breaches else 0)


if __name__ == "__main__":
    main()

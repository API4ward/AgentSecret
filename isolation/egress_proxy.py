"""Default-deny CONNECT proxy for isolated workers. Standard library only.

SG_EGRESS_ALLOW is a comma-separated list of exact host names. Only port 443 is
tunnelled, every resolved address must be public, and the tunnel connects to
the address that was checked. Nothing is logged except allow/deny decisions.
"""
import ipaddress
import os
import select
import socket
from socketserver import StreamRequestHandler, ThreadingTCPServer
import sys

ALLOW = {h.strip().lower() for h in os.environ.get("SG_EGRESS_ALLOW", "").split(",") if h.strip()}


def resolve_public(host):
    addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("non-public address")
    return addresses[0]


class Proxy(StreamRequestHandler):
    timeout = 15

    def deny(self, status, host=""):
        print(f"deny {status} {host}", file=sys.stderr, flush=True)
        self.wfile.write(f"HTTP/1.1 {status} Denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())

    def handle(self):
        try:
            parts = self.rfile.readline(4097).decode("latin-1").split()
            for _ in range(64):
                if self.rfile.readline(4097) in (b"\r\n", b"\n", b""):
                    break
            else:
                return self.deny(400)
            if len(parts) != 3 or parts[0] != "CONNECT":
                return self.deny(405)
            host, _, port = parts[1].rpartition(":")
            host = host.lower()
            if port != "443" or host not in ALLOW:
                return self.deny(403, host)
            try:
                upstream = socket.create_connection((resolve_public(host), 443), timeout=10)
            except (OSError, ValueError):
                return self.deny(403, host)
        except OSError:
            return
        print(f"allow {host}", file=sys.stderr, flush=True)
        with upstream:
            self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.wfile.flush()
            pair = {self.connection: upstream, upstream: self.connection}
            for s in pair:
                s.settimeout(None)
            while True:
                readable, _, _ = select.select(list(pair), [], [], 600)
                if not readable:
                    return
                for s in readable:
                    try:
                        data = s.recv(65536)
                        if not data:
                            return
                        pair[s].sendall(data)
                    except OSError:
                        return


class Server(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print("egress allow-list: " + (", ".join(sorted(ALLOW)) or "(empty, deny all)"), file=sys.stderr, flush=True)
    Server(("0.0.0.0", 8888), Proxy).serve_forever()

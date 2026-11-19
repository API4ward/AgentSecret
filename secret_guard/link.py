"""Outbound connection from a device (injector or approver) to the relay.

Devices only ever dial out, so they work behind NAT. `call` is either
`Relay.dispatch` (same process, tests) or `http_call(url)`.
"""
import json
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .broker import GuardError
from .seal import sign

MAX_RESPONSE = 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *unused):
        return None


def http_call(url):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise GuardError("relay_url_invalid")
    if parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "localhost"}:
        raise GuardError("relay_requires_tls")
    # No proxies and no redirects: a session token is never forwarded elsewhere.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    base = url.rstrip("/")

    def call(route, body, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            with opener.open(Request(base + route, data=json.dumps(body).encode(), headers=headers, method="POST"), timeout=20) as response:
                data = response.read(MAX_RESPONSE + 1)
        except HTTPError as exc:
            try:
                code = json.loads(exc.read(4096))["error"]
            except Exception:
                code = "relay_request_failed"
            raise GuardError(code if isinstance(code, str) else "relay_request_failed") from None
        except Exception:
            raise GuardError("relay_unreachable") from None
        if len(data) > MAX_RESPONSE:
            raise GuardError("relay_request_failed")
        return json.loads(data)
    return call


class DeviceLink:
    """Signs in with the device key and renews the short session when it lapses."""
    def __init__(self, call, device, private):
        self.call, self.device, self.private, self.token = call, device, private, None

    def login(self):
        c = self.call("/device/challenge", {"device": self.device})
        self.token = self.call("/device/login", {"device": self.device, "challenge": c["challenge"], "signature": sign(self.private, c["message"])})["token"]

    def request(self, route, body):
        if not self.token:
            self.login()
        try:
            return self.call(route, body, self.token)
        except GuardError as exc:
            if str(exc) != "device_unauthorized":
                raise
        self.login()
        return self.call(route, body, self.token)

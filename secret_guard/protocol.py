"""Wire constants shared by the relay server, the injector and the approver.

The injector signs the exact canonical request text. The approver signs a
decision over that same text plus its own device id, so nobody has to
re-serialize JSON to check a signature (a browser and Python disagree on floats).
"""
import hashlib

REQUEST_DOMAIN = "secret-guard/approval/v2"
LOGIN = "secret-guard/login/v1:"
REQUEST = "secret-guard/request/v1:"
DECISION = "secret-guard/decision/v2:"
MAX_REQUEST_TEXT = 8192
USE_TTL = 120
REF_TTL = 28800


def request_message(request_text):
    return REQUEST + request_text


def decision_message(decision, approver, request_text):
    return DECISION + decision + ":" + approver + ":" + request_text


def seal_aad(request_text):
    """Binds a sealed credential to one frozen request."""
    return ("secret-guard/seal/v1:" + hashlib.sha256(request_text.encode()).hexdigest()).encode()

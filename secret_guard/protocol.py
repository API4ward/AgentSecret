"""Wire constants shared by the relay server, the injector and the approver.

The injector signs the exact canonical request text. The approver signs a
decision over that same text plus its own device id, so nobody has to
re-serialize JSON to check a signature (a browser and Python disagree on floats).
"""
import hashlib

REQUEST_DOMAIN = "secret-guard/approval/v2"
LOGIN = "secret-guard/login/v1:"
REQUEST = "secret-guard/request/v1:"
DECISION = "secret-guard/decision/v3:"
RULES = "secret-guard/rules/v1:"
MAX_REQUEST_TEXT = 8192
MAX_RULES_TEXT = 32768
# What the agent's own tools may not read without approval. Set on the approver, signed,
# and enforced by the hook beside the agent. "path" is a file, directory or file-name
# pattern (.env, *.pem, ~/.aws); "text" is a string that may not appear in a tool call.
RULE_KINDS = ("path", "text")
USE_TTL = 120
# A reference is "once" (starts exactly one use request) or "long" (reusable until it
# expires). Either way it lasts at most REF_TTL from approval and every use is approved separately.
REF_TTL = 3600
REF_TYPES = ("once", "long")
# Why a request was not approved. The approver signs the code; the caller sees code and text.
REASONS = {
    "secret_unavailable": "本设备没有这个密码",
    "injector_not_paired": "审批端没有配对这台注入工具",
    "policy_denied": "该密码不允许用于这个仓库",
    "request_changed": "请求与固定操作不符",
    "request_invalid": "请求格式无效",
    "rule_unknown": "这条保护规则已不在审批端上",
    "signature_invalid": "请求签名无效，可能在传输中被改动",
}
# Reasons the injector determines itself.
LOCAL_REASONS = {
    "user_denied": "用户拒绝了这次请求",
    "approver_not_paired": "注入工具没有配对作出决定的审批端",
    "no_response": "审批端在有效期内没有响应",
}
# Trusted CLI errors that deserve a sentence.
ERRORS = {
    "alias_invalid": "别名无效：用 1 到 64 个字母、数字、点、下划线或连字符，每条密码一个别名。",
    "secret_empty": "密码为空。密码内容由你管理，本设备不检查格式，只负责保存、密封并转发。",
    "secret_too_large": "密码超过 64 KB，超出一次密封转发的上限。",
    "repo_invalid": "仓库格式无效：应为 owner/name。",
    "empty_policy": "至少要填一个允许使用的仓库。",
    "rule_invalid": "保护规则无效：路径或文件名不能为空，字符串至少 3 个字符，都不超过 256 个字符。",
    "rule_unknown": "没有这条保护规则。",
}


def request_message(request_text):
    return REQUEST + request_text


def decision_message(decision, approver, request_text, reason=""):
    return DECISION + decision + ":" + reason + ":" + approver + ":" + request_text


def reference_details(kind):
    return {"scope": "task_reference_only", "type": kind, "ttl_seconds": REF_TTL}


def rules_message(rules_text):
    return RULES + rules_text


def valid_rule(rule):
    return (isinstance(rule, dict) and set(rule) == {"kind", "value"} and rule["kind"] in RULE_KINDS
            and isinstance(rule["value"], str) and 0 < len(rule["value"]) <= 256 and rule["value"] == rule["value"].strip()
            and not any(ord(c) < 32 for c in rule["value"]) and (rule["kind"] == "path" or len(rule["value"]) >= 3))


def access_details(tool, rule, summary, call):
    """One tool call of the agent that would read protected content."""
    return {"scope": "read_once", "tool": tool, "rule": rule, "summary": summary, "call": call}


def explain(code):
    return {**REASONS, **LOCAL_REASONS}.get(code, code)


def seal_aad(request_text):
    """Binds a sealed credential to one frozen request."""
    return ("secret-guard/seal/v1:" + hashlib.sha256(request_text.encode()).hexdigest()).encode()

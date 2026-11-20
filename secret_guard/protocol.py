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
MAX_RULES_TEXT = 512 * 1024
# The agent meets a credential in two ways besides asking for one over MCP:
#   reveal: content a tool returned contains a credential; approved, it reaches the agent with a reference in its place
#   fill:   a tool call carries a reference; approved, the reference becomes the credential just before the tool runs
HOOK_KINDS = ("reveal", "fill")
REF = "secretref://"
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
    "copy_unknown": "这个别名下没有这个副本。",
    "rule_invalid": "自动审批规则无效。",
    "choice_invalid": "返回值的选择无效：可以是 default、copy:<副本名>、mock 或 manual:<内容>。",
}


def request_message(request_text):
    return REQUEST + request_text


def decision_message(decision, approver, request_text, reason=""):
    return DECISION + decision + ":" + reason + ":" + approver + ":" + request_text


def reference_details(kind):
    return {"scope": "task_reference_only", "type": kind, "ttl_seconds": REF_TTL}


def rules_message(rules_text):
    return RULES + rules_text


def hook_details(kind, tool, target, summary, call, secrets):
    """One tool call of the agent, as the hook saw it, and the credentials it involves."""
    return {"scope": kind, "tool": tool, "target": target, "summary": summary, "call": call, "secrets": secrets}


def explain(code):
    return {**REASONS, **LOCAL_REASONS}.get(code, code)


def seal_aad(request_text):
    """Binds a sealed credential to one frozen request."""
    return ("secret-guard/seal/v1:" + hashlib.sha256(request_text.encode()).hexdigest()).encode()

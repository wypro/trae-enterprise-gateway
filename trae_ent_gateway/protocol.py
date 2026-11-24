"""协议层：OpenAI 请求体 → Trae 私有 `llm_utils_chat` 请求体 + 伪装头。

移植自 buddy-switch-gateway 的 `trae/payload.rs` 与 `trae/routes.rs::send_llm_chat`，
逐字段对齐。关键实测结论（原仓库注释固化）：

- `model_name` = 名字 + `__dev`，去掉后缀直接 `4023 model is unknown`；
- `function` 上游做模型白名单（错一律 `4001 param is invalid`）；
- `prompt_max_tokens` 固定 168000（省略 → 4001；填 1M → 4001）；
- `content` 只接受数组形态；`tools[].function.parameters` 只接受 JSON 字符串；
- 历史消息里的 `tool_calls[].function` 要改回 `function_call`；
- 上游只支持流式，`stream:false` 由网关本地聚合。
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any

TRAE_AGENT_HOST = "https://trae-api-cn.mchost.guru"
TRAE_LLM_CHAT_PATH = "/api/agent/v3/llm_utils_chat"
TRAE_APP_ID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
TRAE_IDE_VERSION = "0.1.50"
TRAE_IDE_VERSION_CODE = "20260811"
TRAE_USER_AGENT = "TraeClient/TTNet"
TRAE_ACCOUNT_BASE_CN = "https://api.trae.cn"
TRAE_ENTITLEMENT_PATH = "/trae/api/v2/pay/ide_user_ent_usage"

DEFAULT_MODEL = "deepseek-v4.1-flash"

# 历史别名（与客户端清单不一致的名字才登记；其余按派生规则 `名字 + __dev`）
MODEL_ALIASES: dict[str, tuple[str, str]] = {
    "deepseek-v4-flash": ("DeepSeek-V4-Flash", "deepseek_v4_flash__dev"),
    "deepseek-v4-flash-official": ("DeepSeek-V4-Flash-Official", "DeepSeek-V4-Flash-Official__dev"),
    "deepseek-v4-pro": ("DeepSeek-V4-Pro", "deepseek_v4_pro__dev"),
    "glm-5.2": ("glm-5.2", "glm-5.2__dev"),
    "glm-5.3": ("glm-5.3", "glm-5.3__dev"),
    "doubao-seed-2.1-pro": ("Doubao-Seed-2.1-Pro", "Doubao-Seed-2.1-Pro__dev"),
    "seed-code-pro-0430": ("Doubao-Seed-2.1-Pro", "Doubao-Seed-2.1-Pro__dev"),
    "doubao-seed-2.1-turbo": ("Doubao-Seed-2.1-Turbo", "Doubao-Seed-2.1-Turbo__dev"),
    "kimi-k2.7-code": ("kimi-k2.7-code", "kimi-k2.7-code__dev"),
    "minimax-m3": ("minimax-m3", "minimax-m3__dev"),
}

# /v1/models 静态兜底清单（solo_work_lite 分组实测口径 + 历史对外名）
MODEL_NAMES: list[str] = [
    "Doubao-Seed-Evolving",
    "Doubao-Seed-2.1-Pro",
    "Doubao-Seed-2.1-Turbo",
    "step-5-preview",
    "glm-5.3",
    "glm-5.2",
    "deepseek-v4.1-flash",
    "DeepSeek-V4-Flash-Official",
    "DeepSeek-V4-Pro-Official",
    "kimi-k3",
    "kimi-k2.7-code",
    "kimi-k2.6",
    "minimax-m3",
    "qwen3.8-max",
    "qwen-3.7-plus",
    "deepseek-v4-flash",
    "deepseek-v4-pro",
    "glm-5-turbo",
    "glm-5",
    "sagitta",
    "aquila",
]
DEFAULT_CONTEXT_LENGTH = 131_072


def model_config(model: str) -> tuple[str, str]:
    """`模型名 → (config_name, model_name)`。未知名字按派生规则，不回落默认模型。"""
    name = (model or "").strip() or DEFAULT_MODEL
    known = MODEL_ALIASES.get(name.lower())
    if known:
        return known
    return name, f"{name}__dev"


def model_of(body: dict[str, Any], default_model: str) -> str:
    value = body.get("model")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default_model


def wants_stream(body: dict[str, Any]) -> bool:
    return bool(body.get("stream"))


def uuid_like() -> str:
    return uuid.uuid4().hex


def trace_id() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# 请求体改写
# ---------------------------------------------------------------------------

def _normalize_messages(body: dict[str, Any]) -> None:
    messages = body.get("messages")
    if not isinstance(messages, list):
        return
    for message in messages:
        if not isinstance(message, dict):
            continue
        if message.get("role") == "assistant":
            calls = message.get("tool_calls")
            if isinstance(calls, list):
                kept = []
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    call = dict(call)
                    function = call.pop("function", None)
                    if function is not None:
                        call["function_call"] = function
                    fc = call.get("function_call")
                    named = isinstance(fc, dict) and bool((fc.get("name") or "").strip())
                    if named:
                        kept.append(call)
                if kept:
                    message["tool_calls"] = kept
                else:
                    message.pop("tool_calls", None)
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = [{"type": "text", "text": content}]


def _normalize_tool_choice(body: dict[str, Any]) -> None:
    choice = body.pop("tool_choice", None)
    if choice is None:
        return

    def suppress() -> None:
        body.pop("tools", None)
        body.pop("functions", None)

    if isinstance(choice, str):
        if choice.strip().lower() == "none":
            suppress()
        else:
            body["tool_choice"] = choice
        return
    if isinstance(choice, dict):
        kind = str(choice.get("type") or "").lower()
        if kind == "none":
            suppress()
        elif kind in ("auto", "required"):
            body["tool_choice"] = kind
        elif kind == "function":
            function = choice.get("function") or {}
            name = str(function.get("name") or choice.get("name") or "").strip() or "auto"
            body["tool_choice"] = name


def _normalize_tools(body: dict[str, Any]) -> None:
    tools = body.get("tools")
    if not isinstance(tools, list):
        return
    cleaned = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool = dict(tool)
        function = tool.get("function")
        if isinstance(function, dict):
            function = dict(function)
            parameters = function.get("parameters")
            if isinstance(parameters, dict):
                function["parameters"] = json.dumps(parameters, ensure_ascii=False)
            tool["function"] = function
        if tool.get("function_call") and not isinstance(tool.get("function_call"), dict):
            continue
        fc = tool.get("function_call")
        if isinstance(fc, dict) and not str(fc.get("name") or "").strip():
            continue
        cleaned.append(tool)
    if cleaned:
        body["tools"] = cleaned
    else:
        body.pop("tools", None)


def content_fingerprint(body: dict[str, Any]) -> str | None:
    """首轮指令 + 首条 user 消息的指纹（多轮追加历史后仍稳定）。"""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return None
    instructions: list[tuple[str, str]] = []
    user_text: str | None = None
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")
        if isinstance(content, str):
            text: str | None = content
        elif content is None:
            text = None
        else:
            text = json.dumps(content, ensure_ascii=False)
        if role in ("system", "developer") and text is not None and user_text is None:
            instructions.append((str(role), text))
        elif role == "user" and text is not None and user_text is None:
            user_text = text
        if user_text is not None:
            break
    parts = [f"{role}:{len(text)}:{text}" for role, text in instructions]
    if user_text is not None:
        parts.append(f"user:{len(user_text)}:{user_text}")
    return "|".join(parts) if parts else None


def conversation_identity_source(body: dict[str, Any]) -> str | None:
    """对话稳定标识原文。优先级：显式会话字段 > 内容指纹 > user。"""
    def nonempty(value: Any) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    value = nonempty(body.get("session_id"))
    if value:
        return f"session:{value}"
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    value = (
        nonempty(body.get("conversation_id"))
        or nonempty(metadata.get("conversation_id"))
        or nonempty(metadata.get("conversationId"))
    )
    if value:
        return f"conversation:{value}"
    value = nonempty(body.get("prompt_cache_key"))
    if value:
        return f"cache_key:{value}"
    value = nonempty(metadata.get("session_id"))
    if value:
        return f"metadata:{value}"
    fingerprint = content_fingerprint(body)
    if fingerprint:
        return fingerprint
    value = nonempty(body.get("user"))
    if value:
        return f"user:{value}"
    return None


def stable_conversation_id(source: str, salt: str) -> str:
    """SHA256(盐|原文) 前 16 字节 → UUID v4 位形（上游只认标准形态）。"""
    digest = hashlib.sha256(f"{salt}|{source}".encode()).digest()[:16]
    b = bytearray(digest)
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def conversation_sticky_identity(body: dict[str, Any]) -> str | None:
    source = conversation_identity_source(body)
    if source is None:
        return None
    return stable_conversation_id(source, "sticky:")


def set_session_id(body: dict[str, Any], identity: str | None) -> None:
    """把 header 侧会话身份写进 body（上游从 session_id 派生 provider 会话）。"""
    if identity and identity.strip() and isinstance(body, dict):
        body["session_id"] = identity.strip()


def prepare_llm_chat_body(
    body: dict[str, Any],
    *,
    function: str,
    package_type: str,
    default_model: str,
    uid: str,
    device_id: str,
    machine_id: str,
    max_mode: bool,
) -> dict[str, Any]:
    """OpenAI 请求体 → `llm_utils_chat` 请求体（逐字段对齐 payload.rs）。"""
    object_ = dict(body)
    _normalize_messages(object_)
    identity_source = conversation_identity_source(object_)
    _normalize_tool_choice(object_)
    _normalize_tools(object_)

    model = model_of(object_, default_model)
    config_name, model_name = model_config(model)

    object_["config_name"] = config_name
    object_["model_name"] = model_name
    object_["stream"] = True  # 上游只支持流式；非流式由网关聚合
    object_["function"] = function

    def derive(salt: str) -> str:
        if identity_source:
            return stable_conversation_id(f"{identity_source}|uid:{uid}", salt)
        return str(uuid.uuid4())

    object_["conversation_id"] = derive("conv:")
    object_["user_id"] = uid
    object_["session_id"] = derive("sess:")
    object_["device_id"] = device_id
    object_["machine_id"] = machine_id
    object_["project_id"] = derive("proj:")
    object_["workspace_id"] = "e04cdd"
    # ★ 固定 168000，不可配置：参考实现真机实测矩阵——省略 → 4001、填 1M → 4001、
    #   唯有 168000 → 200（客户端写死的魔法常量）。它不钳制真实上下文（180051
    #   prompt_tokens 的请求照样 200），1M 窗口由上游内部决策。
    object_["prompt_max_tokens"] = 168_000
    object_["mode"] = "FunctionCall"
    object_["ide_version"] = TRAE_IDE_VERSION
    object_["ide_version_code"] = TRAE_IDE_VERSION_CODE
    object_["app_id"] = TRAE_APP_ID
    object_["package_type"] = package_type
    if max_mode:
        object_["is_max_mode"] = True
    return object_


# ---------------------------------------------------------------------------
# 出站伪装头
# ---------------------------------------------------------------------------

def build_chat_headers(jwt: str, device_id: str, machine_id: str) -> dict[str, str]:
    """`llm_utils_chat` 请求头（逐字对齐 send_llm_chat）。x-ide-token 用裸 JWT。"""
    trace = trace_id()
    return {
        "content-type": "application/json",
        "accept": "*/*",
        "accept-encoding": "identity",
        "user-agent": TRAE_USER_AGENT,
        "referer": f"{TRAE_AGENT_HOST}{TRAE_LLM_CHAT_PATH}",
        "x-ide-token": jwt,
        "x-app-id": TRAE_APP_ID,
        "x-app-version": "default",
        "x-app-version-code": TRAE_IDE_VERSION_CODE,
        "x-ide-version": TRAE_IDE_VERSION,
        "x-ide-version-code": TRAE_IDE_VERSION_CODE,
        "x-ide-version-type": "stable",
        "x-device-type": "windows",
        "x-device-brand": "CREFG-XX",
        "x-device-cpu": "Intel",
        "x-device-id": device_id,
        "x-machine-id": machine_id,
        "x-os-version": "Windows 11 Home China",
        "request-traffic-type": "prod",
        "package-type": "stable_cn",
        "x-lgw-req-sdk-type": "3",
        "x-lscbd-aid": "787976",
        "x-lscbd-platform": "windows",
        "x-ss-dp": "787976",
        "app-version": TRAE_IDE_VERSION,
        "x-custom-trace-id": trace[:16],
        "x-flow-traceparent": f"04-{trace[3:35]}-{uuid_like()}-01",
        "x-tt-trace-id": trace,
        "x-request-id": f"req_{uuid_like()}",
    }


def build_account_headers(jwt: str, device_id: str, machine_id: str) -> dict[str, str]:
    """api.trae.cn（签到 / 额度）请求头。"""
    return {
        "accept": "*/*",
        "content-type": "application/json",
        "request-traffic-type": "prod",
        "user-agent": TRAE_USER_AGENT,
        "x-agent-host-type": "0",
        "x-app-id": TRAE_APP_ID,
        "x-app-version": "default",
        "x-app-version-code": TRAE_IDE_VERSION_CODE,
        "x-bridge-transport": "aha",
        "x-custom-trace-id": uuid_like(),
        "x-device-brand": "MacBookPro18,3",
        "x-device-cpu": "Apple",
        "x-device-type": "mac",
        "x-device-id": device_id,
        "x-machine-id": machine_id,
        "x-ide-token": jwt,
    }


def sanitize_model_id(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._/-]", "-", name)

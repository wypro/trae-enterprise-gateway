"""Anthropic Messages API（/v1/messages）适配层。

入站：Anthropic 请求（system/messages content blocks/tools.input_schema…）→ chat 请求；
出站：chat 回复（聚合 JSON 或流式 chunk）→ Anthropic 响应对象 / SSE 事件流。

事件序列（对齐 Anthropic 规范 + 参考仓库 issue #139/#154 教训）：
    message_start（input_tokens 占位，message_delta 用真实值纠正）
    → content_block_start(text) → content_block_delta(text_delta)* → content_block_stop
    → content_block_start(tool_use) → content_block_delta(input_json_delta)* → content_block_stop
    → message_delta（stop_reason + 累积 usage）→ message_stop
错误帧：只发 `event: error`，**不补** message_delta/stop（客户端见到 error 即终止）。

reasoning_content（上游思考流）不映射 thinking 块：Anthropic thinking 需要上游签名，
伪造会污染回传上下文；Claude 客户端只依赖 text/tool_use 即可正常工作。
"""

from __future__ import annotations

import json
import time
from typing import Any

# ---------------------------------------------------------------------------
# 入站转换：Anthropic 请求 → chat 请求
# ---------------------------------------------------------------------------

_PASSTHROUGH_KEYS = ("temperature", "top_p", "stream", "user")


def _system_to_text(system: Any) -> str:
    if system is None:
        return ""
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return "\n".join(
            str(block.get("text") or "") for block in system
            if isinstance(block, dict) and block.get("type") == "text"
        ).strip()
    return str(system)


def _image_part(source: dict[str, Any]) -> dict[str, Any] | None:
    """Anthropic image source → OpenAI image_url part。仅支持 base64 / url。"""
    kind = source.get("type")
    if kind == "base64":
        media = str(source.get("media_type") or "image/png")
        data = str(source.get("data") or "")
        if data:
            return {"type": "image_url", "image_url": {"url": f"data:{media};base64,{data}"}}
    elif kind == "url":
        url = str(source.get("url") or "")
        if url.startswith(("http://", "https://")):
            return {"type": "image_url", "image_url": {"url": url}}
    return None  # file_id 等平台内形态无法透传


def _user_blocks_to_content(blocks: list[dict[str, Any]]) -> Any:
    """user 消息 content blocks → chat content（纯文本回 str，含图回 parts 数组）。"""
    texts: list[str] = []
    images: list[dict[str, Any]] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "text":
            texts.append(str(block.get("text") or ""))
        elif kind == "image":
            part = _image_part(block.get("source") or {})
            if part:
                images.append(part)
        elif kind == "tool_result":
            # 防御：tool_result 出现在 user 消息里（旧形态），转 tool 文本
            texts.append(_tool_result_text(block))
    if images:
        parts: list[dict[str, Any]] = []
        text = "\n".join(t for t in texts if t)
        if text:
            parts.append({"type": "text", "text": text})
        parts.extend(images)
        return parts
    return "\n".join(t for t in texts if t)


def _tool_result_text(block: dict[str, Any]) -> str:
    content = block.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(item.get("text") or "") for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        )
    return ""


def _convert_tools(tools: Any) -> Any:
    if not isinstance(tools, list):
        return tools
    converted = []
    for tool in tools:
        if isinstance(tool, dict) and tool.get("name"):
            converted.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description"),
                    "parameters": tool.get("input_schema") or {"type": "object", "properties": {}},
                },
            })
    return converted


def _convert_tool_choice(choice: Any) -> Any:
    if not isinstance(choice, dict):
        return choice
    kind = choice.get("type")
    if kind == "auto":
        return "auto"
    if kind == "any":
        return "required"
    if kind == "tool" and choice.get("name"):
        return {"type": "function", "function": {"name": choice["name"]}}
    return None  # 未知形态交给管线默认（auto）


def parse_request(body: dict[str, Any]) -> dict[str, Any]:
    """Anthropic /v1/messages 请求体 → chat completions 请求体。"""
    messages: list[dict[str, Any]] = []
    system = _system_to_text(body.get("system"))
    if system:
        messages.append({"role": "system", "content": system})

    for item in body.get("messages") or []:
        if not isinstance(item, dict):
            continue
        role = item.get("role") or "user"
        content = item.get("content")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            continue

        if role == "assistant":
            # assistant：text 块 + tool_use 块 → 单条 assistant 消息（content + tool_calls）
            texts: list[str] = []
            tool_calls: list[dict[str, Any]] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                kind = block.get("type")
                if kind == "text":
                    texts.append(str(block.get("text") or ""))
                elif kind == "tool_use":
                    tool_calls.append({
                        "id": str(block.get("id") or ""),
                        "type": "function",
                        "function": {
                            "name": str(block.get("name") or ""),
                            "arguments": json.dumps(block.get("input") or {}, ensure_ascii=False),
                        },
                    })
                # thinking 块：本地状态，跳过
            message: dict[str, Any] = {"role": "assistant", "content": "\n".join(t for t in texts if t)}
            if tool_calls:
                message["tool_calls"] = tool_calls
            messages.append(message)
        else:
            # user：text/image 块数组；tool_result 块单独拆成 role=tool 消息（须保持顺序）
            pending: list[dict[str, Any]] = []
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_result":
                    if pending:
                        messages.append({"role": "user", "content": _user_blocks_to_content(pending)})
                        pending = []
                    messages.append({
                        "role": "tool",
                        "tool_call_id": str(block.get("tool_use_id") or ""),
                        "content": _tool_result_text(block),
                    })
                else:
                    pending.append(block)
            if pending:
                messages.append({"role": "user", "content": _user_blocks_to_content(pending)})

    chat: dict[str, Any] = {
        "model": body.get("model"),
        "messages": messages,
        "stream": bool(body.get("stream")),
    }
    for key in _PASSTHROUGH_KEYS:
        if body.get(key) is not None:
            chat[key] = body[key]
    if body.get("max_tokens") is not None:
        chat["max_tokens"] = body["max_tokens"]
    if body.get("stop_sequences"):
        chat["stop"] = body["stop_sequences"]
    if body.get("tools") is not None:
        chat["tools"] = _convert_tools(body["tools"])
    choice = _convert_tool_choice(body.get("tool_choice"))
    if choice is not None:
        chat["tool_choice"] = choice
    return chat


# ---------------------------------------------------------------------------
# 出站转换：chat 回复 → Anthropic 响应
# ---------------------------------------------------------------------------

_STOP_REASON_MAP = {
    "tool_calls": "tool_use",
    "length": "max_tokens",
    "stop": "end_turn",
    "content_filter": "end_turn",
}


def map_stop_reason(finish_reason: str | None) -> str:
    return _STOP_REASON_MAP.get(finish_reason or "", "end_turn")


def _anthropic_error_type(kind: str) -> str:
    return {
        "authentication_error": "authentication_error",
        "invalid_request_error": "invalid_request_error",
        "rate_limit_error": "rate_limit_error",
        "permission_error": "permission_error",
        "not_found_error": "not_found_error",
    }.get(kind, "api_error")


def error_payload(kind: str, message: str) -> dict[str, Any]:
    return {"type": "error", "error": {"type": _anthropic_error_type(kind), "message": message}}


def to_message_object(chat_payload: dict[str, Any], model: str, msg_id: str) -> dict[str, Any]:
    """chat 非流式回复 → Anthropic message 对象。"""
    choice = (chat_payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    usage = chat_payload.get("usage") or {}
    content: list[dict[str, Any]] = []

    text = message.get("content") or ""
    if text:
        content.append({"type": "text", "text": text})
    for tool_call in message.get("tool_calls") or []:
        fn = tool_call.get("function") or {}
        try:
            arguments = json.loads(fn.get("arguments") or "{}")
        except ValueError:
            arguments = {}
        content.append({
            "type": "tool_use",
            "id": tool_call.get("id") or f"toolu_{len(content)}",
            "name": fn.get("name") or "",
            "input": arguments,
        })
    return {
        "id": msg_id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": map_stop_reason(choice.get("finish_reason")),
        "stop_sequence": None,
        "usage": {
            "input_tokens": usage.get("prompt_tokens") or 0,
            "output_tokens": usage.get("completion_tokens") or 0,
        },
    }


# ---------------------------------------------------------------------------
# 出站转换：chat 流式 chunk → Anthropic SSE
# ---------------------------------------------------------------------------

def _sse(event_type: str, payload: dict[str, Any]) -> str:
    return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


class AnthropicStreamAdapter:
    """消费 chat chunk dict，产出 Anthropic SSE 行。与 StreamConverter 串联使用。"""

    def __init__(self, msg_id: str, model: str) -> None:
        self._msg_id = msg_id
        self._model = model
        self._seq_index = 0          # content block index
        self._text_open: int | None = None
        self._tool_index: dict[int, int] = {}  # chat tool index → block index
        self._usage: dict[str, int] | None = None
        self._stop_reason: str | None = None
        self._finished = False

    def start(self) -> list[str]:
        # ★ message_start 的 input_tokens 是占位值（上游用量流末才到），
        #   message_delta 会带真实值纠正（issue #139）
        return [_sse("message_start", {
            "type": "message_start",
            "message": {
                "id": self._msg_id, "type": "message", "role": "assistant",
                "model": self._model, "content": [],
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        })]

    def _open_text(self) -> list[str]:
        if self._text_open is not None:
            return []
        self._text_open = self._seq_index
        self._seq_index += 1
        return [_sse("content_block_start", {
            "type": "content_block_start",
            "index": self._text_open,
            "content_block": {"type": "text", "text": ""},
        })]

    def _close_text(self) -> list[str]:
        if self._text_open is None:
            return []
        lines = [_sse("content_block_stop", {"type": "content_block_stop", "index": self._text_open})]
        self._text_open = None
        return lines

    def feed_chat_chunk(self, chunk: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        choices = chunk.get("choices") or []
        choice = choices[0] if choices else {}
        delta = choice.get("delta") or {}

        # reasoning_content：不映射 thinking 块（见模块 docstring），静默丢弃
        text = delta.get("content")
        if text:
            lines.extend(self._open_text())
            lines.append(_sse("content_block_delta", {
                "type": "content_block_delta",
                "index": self._text_open,
                "delta": {"type": "text_delta", "text": text},
            }))

        for call_delta in delta.get("tool_calls") or []:
            upstream_index = int(call_delta.get("index") or 0)
            fn = call_delta.get("function") or {}
            if upstream_index not in self._tool_index:
                lines.extend(self._close_text())  # 文本块先收口（参考实现同序）
                block_index = self._seq_index
                self._seq_index += 1
                self._tool_index[upstream_index] = block_index
                lines.append(_sse("content_block_start", {
                    "type": "content_block_start",
                    "index": block_index,
                    "content_block": {
                        "type": "tool_use",
                        "id": call_delta.get("id") or f"toolu_{upstream_index}",
                        "name": fn.get("name") or "",
                        "input": {},
                    },
                }))
            if fn.get("arguments"):
                lines.append(_sse("content_block_delta", {
                    "type": "content_block_delta",
                    "index": self._tool_index[upstream_index],
                    "delta": {"type": "input_json_delta", "partial_json": fn["arguments"]},
                }))

        if choice.get("finish_reason"):
            self._stop_reason = map_stop_reason(choice.get("finish_reason"))
        if chunk.get("usage"):
            usage = chunk["usage"]
            self._usage = {
                "input_tokens": usage.get("prompt_tokens") or 0,
                "output_tokens": usage.get("completion_tokens") or 0,
            }
        return lines

    def feed_error(self, error_payload_: dict[str, Any]) -> list[str]:
        """chat 错误帧 → `event: error`（不补 message_delta/stop）。"""
        self._finished = True
        error = error_payload_.get("error") or {}
        return [_sse("error", error_payload(
            str(error.get("type") or "api_error"),
            str(error.get("message") or "上游错误"),
        ))]

    def finish(self) -> list[str]:
        if self._finished:
            return []
        self._finished = True
        lines = self._close_text()
        lines.append(_sse("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": self._stop_reason or "end_turn", "stop_sequence": None},
            "usage": self._usage or {"input_tokens": 0, "output_tokens": 0},
        }))
        lines.append(_sse("message_stop", {"type": "message_stop"}))
        return lines

"""OpenAI Responses API（/v1/responses）适配层。

入站：Responses 请求（instructions/input/tools…）→ Chat Completions 请求，复用现有管线；
出站：chat 回复（聚合 JSON 或流式 chunk）→ Responses 对象 / 事件流。

事件序列对齐 OpenAI 规范：
    response.created
    [reasoning]  response.output_item.added → response.reasoning_summary_text.delta*
                 → response.reasoning_summary_text.done → response.output_item.done
    [message]    response.output_item.added → response.content_part.added
                 → response.output_text.delta* → response.content_part.done
                 → response.output_item.done
    [tool_calls] response.output_item.added(type=function_call)
                 → response.function_call_arguments.delta* → response.output_item.done
    response.completed（无 [DONE] 哨兵，Responses SSE 以 completed 事件收尾）
"""

from __future__ import annotations

import json
import time
from typing import Any

# ---------------------------------------------------------------------------
# 入站转换：Responses 请求 → chat 请求
# ---------------------------------------------------------------------------

_PASSTHROUGH_KEYS = (
    "temperature", "top_p", "parallel_tool_calls", "response_format", "stop",
    "user", "seed", "frequency_penalty", "presence_penalty",
)


def _content_to_text(content: Any) -> str:
    """Responses content → 纯文本（instructions / tool output 等仅文本场景）。"""
    return _content_to_parts(content) if not isinstance(content, str) else content


def _content_to_parts(content: Any) -> Any:
    """Responses content → chat content。

    纯文本回 str；含 input_image 时回 OpenAI parts 数组（image_url 原样透传，
    实测 2026-11-23：llm_utils_chat 的 content 数组直接吃 image_url part，
    glm-5.3 正确识别 64×64 纯色测试图）。file_id 形态上游无法解析，跳过。
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return _content_to_text(content)
    texts: list[str] = []
    images: list[dict[str, Any]] = []
    for part in content:
        if isinstance(part, str):
            texts.append(part)
            continue
        if not isinstance(part, dict):
            continue
        kind = part.get("type")
        if kind in ("input_text", "output_text", "text"):
            texts.append(str(part.get("text") or ""))
        elif kind == "input_image":
            url = str(part.get("image_url") or part.get("url") or "").strip()
            if url.startswith(("data:", "http://", "https://")):
                images.append({"type": "image_url", "image_url": {"url": url}})
            # 其余形态（file_id / 未给出 URL）无法透传，静默跳过
        elif kind == "refusal":
            texts.append(str(part.get("refusal") or ""))
    if images:
        parts: list[dict[str, Any]] = []
        text = "\n".join(t for t in texts if t)
        if text:
            parts.append({"type": "text", "text": text})
        parts.extend(images)
        return parts
    return "\n".join(t for t in texts if t)


def _convert_tools(tools: Any) -> Any:
    """Responses 工具定义（扁平 {type,name,description,parameters}）→ chat 嵌套格式。"""
    if not isinstance(tools, list):
        return tools
    converted = []
    for tool in tools:
        if isinstance(tool, dict) and tool.get("type") == "function" and "name" in tool:
            converted.append({
                "type": "function",
                "function": {
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "parameters": tool.get("parameters") or {"type": "object", "properties": {}},
                },
            })
        else:
            converted.append(tool)
    return converted


def _convert_tool_choice(tool_choice: Any) -> Any:
    if isinstance(tool_choice, dict) and tool_choice.get("type") == "function" and "name" in tool_choice:
        return {"type": "function", "function": {"name": tool_choice["name"]}}
    return tool_choice


def parse_request(body: dict[str, Any]) -> dict[str, Any]:
    """Responses 请求体 → chat completions 请求体。"""
    messages: list[dict[str, Any]] = []
    instructions = body.get("instructions")
    if instructions:
        messages.append({"role": "system", "content": _content_to_text(instructions)})

    inp = body.get("input")
    if isinstance(inp, str):
        messages.append({"role": "user", "content": inp})
    elif isinstance(inp, list):
        for item in inp:
            if not isinstance(item, dict):
                continue
            kind = item.get("type") or ("message" if "role" in item else "")
            if kind == "message":
                messages.append({
                    "role": item.get("role") or "user",
                    "content": _content_to_parts(item.get("content")),
                })
            elif kind == "function_call_output":
                messages.append({
                    "role": "tool",
                    "tool_call_id": item.get("call_id") or item.get("id") or "",
                    "content": _content_to_text(item.get("output")),
                })
            elif kind == "function_call":
                messages.append({
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": item.get("call_id") or item.get("id") or "",
                        "type": "function",
                        "function": {
                            "name": item.get("name") or "",
                            "arguments": item.get("arguments") or "{}",
                        },
                    }],
                })
            # reasoning / item_reference：本地状态，无需回放上游

    chat: dict[str, Any] = {
        "model": body.get("model"),
        "messages": messages,
        "stream": bool(body.get("stream")),
    }
    for key in _PASSTHROUGH_KEYS:
        if body.get(key) is not None:
            chat[key] = body[key]
    if body.get("max_output_tokens") is not None:
        chat["max_tokens"] = body["max_output_tokens"]
    if body.get("tools") is not None:
        chat["tools"] = _convert_tools(body["tools"])
    if body.get("tool_choice") is not None:
        chat["tool_choice"] = _convert_tool_choice(body["tool_choice"])
    return chat


# ---------------------------------------------------------------------------
# 出站转换：chat 回复 → Responses 对象
# ---------------------------------------------------------------------------

def _usage_of(chat_payload: dict[str, Any]) -> dict[str, int]:
    usage = chat_payload.get("usage") or {}
    return {
        "input_tokens": usage.get("prompt_tokens") or 0,
        "output_tokens": usage.get("completion_tokens") or 0,
        "total_tokens": usage.get("total_tokens")
        or (usage.get("prompt_tokens") or 0) + (usage.get("completion_tokens") or 0),
    }


def _response_envelope(resp_id: str, model: str, created_at: int) -> dict[str, Any]:
    return {
        "id": resp_id,
        "object": "response",
        "created_at": created_at,
        "status": "in_progress",
        "model": model,
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "metadata": {},
        "output": [],
        "parallel_tool_calls": True,
        "temperature": None,
        "top_p": None,
        "tool_choice": "auto",
        "tools": [],
        "usage": None,
    }


def to_response_object(chat_payload: dict[str, Any], model: str, resp_id: str) -> dict[str, Any]:
    """chat 非流式回复 → Responses response 对象。"""
    choice = (chat_payload.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    created_at = int(time.time())
    response = _response_envelope(resp_id, model, created_at)
    output: list[dict[str, Any]] = []

    reasoning = message.get("reasoning_content")
    if reasoning:
        output.append({
            "type": "reasoning",
            "id": f"{resp_id}-rs",
            "summary": [{"type": "summary_text", "text": reasoning}],
        })
    for tool_call in message.get("tool_calls") or []:
        fn = tool_call.get("function") or {}
        output.append({
            "type": "function_call",
            "id": f"{resp_id}-fc-{tool_call.get('index', len(output))}",
            "call_id": tool_call.get("id") or f"call_{len(output)}",
            "name": fn.get("name") or "",
            "arguments": fn.get("arguments") or "{}",
            "status": "completed",
        })
    output.append({
        "type": "message",
        "id": f"{resp_id}-msg",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": message.get("content") or "", "annotations": []}],
    })

    response["output"] = output
    response["status"] = "completed"
    response["usage"] = _usage_of(chat_payload)
    return response


def error_response(status: int, kind: str, message: str, model: str, resp_id: str) -> dict[str, Any]:
    """错误 → response.failed 对象。"""
    response = _response_envelope(resp_id, model, int(time.time()))
    response["status"] = "failed"
    response["error"] = {"code": kind, "message": message, "param": None, "sequence_number": 0}
    return response


# ---------------------------------------------------------------------------
# 出站转换：chat 流式 chunk → Responses 事件流
# ---------------------------------------------------------------------------

def _sse(event_type: str, payload: dict[str, Any]) -> str:
    payload = {"type": event_type, **payload}
    return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


class ResponsesStreamAdapter:
    """消费 chat chunk dict，产出 Responses SSE 行。与 StreamConverter 串联使用。"""

    def __init__(self, resp_id: str, model: str) -> None:
        self._resp_id = resp_id
        self._model = model
        self._created_at = int(time.time())
        self._seq = 0
        self._output_index = 0
        self._text_parts: list[str] = []
        self._reasoning_parts: list[str] = []
        self._calls: dict[int, dict[str, str]] = {}  # index -> {id,name,args}
        self._opened_item: str | None = None  # "reasoning" | "message" | "call:<idx>"
        self._usage: dict[str, int] | None = None
        self._finished = False

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _item(self, kind: str, index: int) -> dict[str, Any]:
        resp_id = self._resp_id
        if kind == "reasoning":
            return {"type": "reasoning", "id": f"{resp_id}-rs", "summary": []}
        if kind == "message":
            return {"type": "message", "id": f"{resp_id}-msg", "role": "assistant", "status": "in_progress", "content": []}
        call = self._calls[index]
        return {"type": "function_call", "id": f"{resp_id}-fc-{index}", "call_id": call["id"], "name": call["name"], "arguments": "", "status": "in_progress"}

    def _open_item(self, kind: str, index: int = 0) -> list[str]:
        opened = self._opened_item
        already = opened == kind if kind in ("reasoning", "message") else opened == f"call:{index}"
        if already:
            return []
        self._close_item()
        self._opened_item = kind if kind in ("reasoning", "message") else f"call:{index}"
        return [_sse("response.output_item.added", {
            "sequence_number": self._next_seq(),
            "output_index": self._output_index,
            "item": self._item(kind, index),
        })]

    def _close_item(self) -> list[str]:
        if self._opened_item is None:
            return []
        lines: list[str] = []
        output_index = self._output_index
        if self._opened_item == "reasoning":
            text = "".join(self._reasoning_parts)
            lines.append(_sse("response.reasoning_summary_text.done", {
                "sequence_number": self._next_seq(), "item_id": f"{self._resp_id}-rs",
                "output_index": output_index, "summary_index": 0, "text": text,
            }))
            lines.append(_sse("response.output_item.done", {
                "sequence_number": self._next_seq(), "output_index": output_index,
                "item": {"type": "reasoning", "id": f"{self._resp_id}-rs", "summary": [{"type": "summary_text", "text": text}]},
            }))
            self._reasoning_parts = []
        elif self._opened_item == "message":
            text = "".join(self._text_parts)
            lines.append(_sse("response.content_part.done", {
                "sequence_number": self._next_seq(), "item_id": f"{self._resp_id}-msg",
                "output_index": output_index, "content_index": 0,
                "part": {"type": "output_text", "text": text, "annotations": []},
            }))
            lines.append(_sse("response.output_item.done", {
                "sequence_number": self._next_seq(), "output_index": output_index,
                "item": {"type": "message", "id": f"{self._resp_id}-msg", "role": "assistant", "status": "completed",
                          "content": [{"type": "output_text", "text": text, "annotations": []}]},
            }))
            self._text_parts = []
        else:
            index = int(self._opened_item.split(":", 1)[1])
            call = self._calls[index]
            lines.append(_sse("response.output_item.done", {
                "sequence_number": self._next_seq(), "output_index": output_index,
                "item": {"type": "function_call", "id": f"{self._resp_id}-fc-{index}", "call_id": call["id"],
                          "name": call["name"], "arguments": call["args"], "status": "completed"},
            }))
        self._opened_item = None
        self._output_index += 1
        return lines

    def start(self) -> list[str]:
        """流开始：response.created。"""
        return [_sse("response.created", {
            "sequence_number": self._next_seq(),
            "response": _response_envelope(self._resp_id, self._model, self._created_at),
        })]

    def feed_chat_chunk(self, chunk: dict[str, Any]) -> list[str]:
        """喂一个 chat.completion.chunk dict，返回事件行列表。"""
        lines: list[str] = []
        choices = chunk.get("choices") or []
        choice = choices[0] if choices else {}
        delta = choice.get("delta") or {}

        reasoning = delta.get("reasoning_content")
        if reasoning:
            lines.extend(self._open_item("reasoning"))
            self._reasoning_parts.append(reasoning)
            lines.append(_sse("response.reasoning_summary_text.delta", {
                "sequence_number": self._next_seq(), "item_id": f"{self._resp_id}-rs",
                "output_index": self._output_index, "summary_index": 0, "delta": reasoning,
            }))

        content = delta.get("content")
        if content:
            lines.extend(self._open_item("message"))
            if not self._text_parts:  # 消息第一个 delta：加 content_part.added
                lines.append(_sse("response.content_part.added", {
                    "sequence_number": self._next_seq(), "item_id": f"{self._resp_id}-msg",
                    "output_index": self._output_index, "content_index": 0,
                    "part": {"type": "output_text", "text": "", "annotations": []},
                }))
            self._text_parts.append(content)
            lines.append(_sse("response.output_text.delta", {
                "sequence_number": self._next_seq(), "item_id": f"{self._resp_id}-msg",
                "output_index": self._output_index, "content_index": 0, "delta": content,
            }))

        for call_delta in delta.get("tool_calls") or []:
            index = int(call_delta.get("index") or 0)
            fn = call_delta.get("function") or {}
            call = self._calls.setdefault(index, {"id": call_delta.get("id") or f"call_{index}", "name": "", "args": ""})
            if call_delta.get("id"):
                call["id"] = call_delta["id"]
            if fn.get("name"):
                call["name"] = fn["name"]
            lines.extend(self._open_item("call", index))
            if fn.get("arguments"):
                call["args"] += fn["arguments"]
                lines.append(_sse("response.function_call_arguments.delta", {
                    "sequence_number": self._next_seq(), "item_id": f"{self._resp_id}-fc-{index}",
                    "output_index": self._output_index, "delta": fn["arguments"],
                }))

        if choice.get("finish_reason") or chunk.get("usage"):
            if chunk.get("usage"):
                self._usage = _usage_of(chunk)
        return lines

    def feed_error(self, error_payload: dict[str, Any]) -> list[str]:
        """chat 错误帧 → response.failed 事件。"""
        self._finished = True
        error = error_payload.get("error") or {}
        response = _response_envelope(self._resp_id, self._model, self._created_at)
        response["status"] = "failed"
        response["error"] = {
            "code": str(error.get("code") or error.get("type") or "upstream_error"),
            "message": str(error.get("message") or "上游错误"),
            "param": None,
        }
        return [_sse("response.failed", {"sequence_number": self._next_seq(), "response": response})]

    def finish(self) -> list[str]:
        """chat 流收尾（[DONE] 前）：关闭未完 item + response.completed。"""
        if self._finished:
            return []
        self._finished = True
        # _close_item 会清空累计 parts，先快照用于重建最终 output
        reasoning_text = "".join(self._reasoning_parts)
        message_text = "".join(self._text_parts)
        lines = self._close_item()
        response = _response_envelope(self._resp_id, self._model, self._created_at)
        output: list[dict[str, Any]] = []
        if reasoning_text:
            output.append({"type": "reasoning", "id": f"{self._resp_id}-rs",
                            "summary": [{"type": "summary_text", "text": reasoning_text}]})
        for index in sorted(self._calls):
            call = self._calls[index]
            output.append({"type": "function_call", "id": f"{self._resp_id}-fc-{index}", "call_id": call["id"],
                            "name": call["name"], "arguments": call["args"], "status": "completed"})
        output.append({"type": "message", "id": f"{self._resp_id}-msg", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": message_text, "annotations": []}]})
        response["output"] = output
        response["status"] = "completed"
        response["usage"] = self._usage or {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        lines.append(_sse("response.completed", {"sequence_number": self._next_seq(), "response": response}))
        return lines

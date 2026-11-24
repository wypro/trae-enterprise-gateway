"""SOLO SSE → OpenAI SSE 转换（移植自 trae/sse.rs）。

上游是私有事件流（`event: output` / `token_usage` / `done` / `error`，行前带 `id:N`），
必须逐事件转换。两条硬约束：
1. 绝不悬挂连接：任何收尾都必须补 `data: [DONE]`；
2. `stream:false` 也走这里，本地聚合成单个 chat.completion。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator


@dataclass
class TokenUsage:
    prompt: int = 0
    completion: int = 0
    total: int = 0
    reasoning: int = 0
    cached: int | None = None

    def is_meaningful(self) -> bool:
        return self.total > 0 or self.prompt > 0 or self.completion > 0

    def to_openai(self) -> dict[str, Any]:
        usage: dict[str, Any] = {
            "prompt_tokens": self.prompt,
            "completion_tokens": self.completion,
            "total_tokens": self.total,
        }
        # cached 只在真有命中量时写（对外 wire 形状，多一个键会被严格客户端拒绝）
        if self.cached is not None:
            usage["prompt_tokens_details"] = {"cached_tokens": self.cached}
        return usage

    @staticmethod
    def from_value(value: dict[str, Any]) -> "TokenUsage":
        def read(key: str) -> int:
            v = value.get(key)
            return int(v) if isinstance(v, (int, float)) else 0

        prompt = read("prompt_tokens")
        completion = read("completion_tokens")
        total = read("total_tokens") or (prompt + completion)
        return TokenUsage(
            prompt=prompt,
            completion=completion,
            total=total,
            reasoning=read("reasoning_tokens"),
            cached=_cached_tokens_of(value),
        )


def _cached_tokens_of(usage: dict[str, Any]) -> int | None:
    def read(key: str) -> int | None:
        v = usage.get(key)
        return int(v) if isinstance(v, (int, float)) else None

    details = usage.get("prompt_tokens_details")
    hit = (
        read("prompt_cache_hit_tokens")
        or (_read_cache_details(details))
        or read("cache_read_input_tokens")
        or read("cached_tokens")
    )
    if hit is None:
        return None
    return min(hit, read("prompt_tokens") or 0)


def _read_cache_details(details: Any) -> int | None:
    if isinstance(details, dict):
        v = details.get("cached_tokens")
        if isinstance(v, (int, float)):
            return int(v)
    return None


def _cache_pool_assigned(metadata: dict[str, Any]) -> bool | None:
    record = metadata.get("prompt_cache_pool_record")
    if record is None and "prompt_cache_pool_record" not in metadata:
        return None
    if isinstance(record, (dict, list)):
        return True
    return False  # 显式 null / 标量 = 明确无池


@dataclass
class SoloEvent:
    event: str = ""
    response: str = ""
    reasoning: str = ""
    tool_calls: Any = None
    usage: TokenUsage | None = None
    cache_pool_assigned: bool | None = None
    finish_reason: str = ""
    error_code: int | None = None
    error_message: str = ""


class SoloParser:
    """增量 SSE 解析器：跨 chunk 保留未完成的行与未结束的事件（按字节缓冲）。"""

    def __init__(self) -> None:
        self._buffer = b""
        self._event = ""
        self._data = ""

    def feed(self, chunk: bytes) -> list[SoloEvent]:
        self._buffer += chunk
        events: list[SoloEvent] = []
        while b"\n" in self._buffer:
            index = self._buffer.index(b"\n")
            line_bytes, self._buffer = self._buffer[: index + 1], self._buffer[index + 1:]
            line = line_bytes[:-1].decode("utf-8", errors="replace").rstrip("\r")
            event = self._scan_line(line)
            if event is not None:
                events.append(event)
        return events

    def finish(self) -> list[SoloEvent]:
        events: list[SoloEvent] = []
        if self._buffer:
            tail, self._buffer = self._buffer, b""
            for line in tail.decode("utf-8", errors="replace").splitlines():
                event = self._scan_line(line.rstrip("\r"))
                if event is not None:
                    events.append(event)
        if self._event or self._data:
            events.append(self._build_event())
        return events

    def _scan_line(self, line: str) -> SoloEvent | None:
        if not line:
            if not self._event and not self._data:
                return None
            return self._build_event()
        if line.startswith("event:"):
            self._event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            self._data += line[len("data:"):]
        return None  # id:N / retry: 等字段忽略

    def _build_event(self) -> SoloEvent:
        event, self._event = self._event, ""
        data, self._data = self._data, ""
        return parse_event(event, data)


def parse_event(event: str, data: str) -> SoloEvent:
    parsed = SoloEvent(event=event.strip())
    if not data:
        return parsed
    try:
        raw = json.loads(data)
    except ValueError:
        return parsed
    if not isinstance(raw, dict):
        return parsed

    if parsed.event in ("output", "thought"):
        text = raw.get("response")
        if not isinstance(text, str):
            text = raw.get("thought")
        if isinstance(text, str):
            parsed.response = text
        reasoning = raw.get("reasoning_content")
        if isinstance(reasoning, str):
            parsed.reasoning = reasoning
        calls = raw.get("tool_calls")
        if calls is not None:
            parsed.tool_calls = calls
    elif parsed.event == "token_usage":
        parsed.usage = TokenUsage.from_value(raw)
    elif parsed.event == "metadata":
        parsed.cache_pool_assigned = _cache_pool_assigned(raw)
    elif parsed.event == "done":
        parsed.finish_reason = raw.get("finish_reason") or "stop"
    elif parsed.event == "turn_completion":
        parsed.finish_reason = "stop"
    elif parsed.event == "error":
        code = raw.get("code")
        parsed.error_code = int(code) if isinstance(code, (int, float)) else None
        parsed.error_message = raw.get("message") or "上游返回了未描述的错误"
    return parsed


# ---------------------------------------------------------------------------
# 工具调用增量累加器（上游 tool_calls 是逐帧增量，按帧各自输出会拆成残缺条目）
# ---------------------------------------------------------------------------

@dataclass
class _ToolCallSlot:
    id: str = ""
    name: str = ""
    arguments: str = ""
    announced: bool = False


class ToolCallAccumulator:
    def __init__(self) -> None:
        self.slots: list[_ToolCallSlot] = []
        self._by_upstream: dict[int, int] = {}
        self._by_id: dict[str, int] = {}
        self._last: int | None = None

    def _push_slot(self) -> int:
        self.slots.append(_ToolCallSlot())
        return len(self.slots) - 1

    def _slot_of(self, call: dict[str, Any]) -> int:
        index = call.get("index")
        if isinstance(index, (int, float)):
            index = int(index)
            slot = self._by_upstream.get(index)
            if slot is None:
                slot = self._push_slot()
                self._by_upstream[index] = slot
            self._last = slot
            return slot
        call_id = call.get("id")
        if isinstance(call_id, str) and call_id:
            slot = self._by_id.get(call_id)
            if slot is not None:
                self._last = slot
                return slot
        elif self._last is not None:
            return self._last  # 既无 index 也无 id：续写最近一次调用
        slot = self._push_slot()
        self._last = slot
        return slot

    def _absorb(self, call: dict[str, Any]) -> dict[str, Any]:
        slot_index = self._slot_of(call)
        slot = self.slots[slot_index]
        function = call.get("function") or call.get("function_call") or {}
        if not isinstance(function, dict):
            function = {}
        absorbed = {"slot": slot_index, "id": None, "name": "", "arguments": ""}

        call_id = call.get("id")
        if isinstance(call_id, str) and call_id and not slot.id:
            slot.id = call_id
            self._by_id[call_id] = slot_index
            absorbed["id"] = call_id

        name = function.get("name") or ""
        if name:
            known = slot.name
            if known and name.startswith(known):
                absorbed["name"] = name[len(known):]
                slot.name = name
            elif not known.startswith(name):
                absorbed["name"] = name
                slot.name += name

        arguments = function.get("arguments")
        if arguments is None:
            text = ""
        elif isinstance(arguments, str):
            text = arguments
        elif isinstance(arguments, (dict, list)):
            text = json.dumps(arguments, ensure_ascii=False)
        else:
            text = ""
        if text and slot.arguments != text:  # 整帧重放不重复拼接
            slot.arguments += text
            absorbed["arguments"] = text
        return absorbed

    def absorb_all(self, value: Any) -> None:
        if isinstance(value, list):
            for call in value:
                if isinstance(call, dict):
                    self._absorb(call)

    def has_calls(self) -> bool:
        return any(
            slot.id or slot.name or slot.arguments for slot in self.slots
        )

    def streaming_deltas(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        entries = []
        for call in value:
            if not isinstance(call, dict):
                continue
            absorbed = self._absorb(call)
            slot = self.slots[absorbed["slot"]]
            has_payload = absorbed["id"] is not None or absorbed["name"] or absorbed["arguments"]
            if slot.announced and not has_payload:
                continue  # 纯重复帧不下发空分片
            entry: dict[str, Any] = {"index": absorbed["slot"]}
            if not slot.announced:
                slot.announced = True
                entry["type"] = "function"
                entry["id"] = slot.id or f"call_{absorbed['slot']}"
            elif absorbed["id"]:
                entry["id"] = absorbed["id"]  # 晚到的真 id 补发一次
            function: dict[str, Any] = {}
            if absorbed["name"]:
                function["name"] = absorbed["name"]
            if absorbed["arguments"]:
                function["arguments"] = absorbed["arguments"]
            if function:
                entry["function"] = function
            entries.append(entry)
        return entries

    def merged(self) -> list[dict[str, Any]]:
        result = []
        for index, slot in enumerate(self.slots):
            if not (slot.id or slot.name or slot.arguments):
                continue
            result.append({
                "id": slot.id or f"call_{index}",
                "type": "function",
                "function": {"name": slot.name, "arguments": slot.arguments},
            })
        return result


def promote_tool_finish(finish: str, has_calls: bool) -> str:
    """有工具调用时 finish_reason 必须是 tool_calls（上游 done 固定报 stop）。"""
    if has_calls and (not finish or finish == "stop"):
        return "tool_calls"
    return finish


# ---------------------------------------------------------------------------
# OpenAI 输出
# ---------------------------------------------------------------------------

def _now_secs() -> int:
    return int(time.time())


def _chunk_line(
    chat_id: str,
    model: str,
    delta: dict[str, Any],
    finish_reason: str,
    usage: TokenUsage | None,
) -> str:
    choice: dict[str, Any] = {"index": 0, "delta": delta}
    if finish_reason:
        choice["finish_reason"] = finish_reason
    chunk: dict[str, Any] = {
        "id": chat_id,
        "object": "chat.completion.chunk",
        "created": _now_secs(),
        "model": model,
        "choices": [choice],
    }
    if usage is not None and usage.is_meaningful():
        chunk["usage"] = usage.to_openai()
    return f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"


DONE_LINE = "data: [DONE]\n\n"


@dataclass
class StreamOutcome:
    error: tuple[int, str] | None = None  # (code, message)
    usage: TokenUsage = field(default_factory=TokenUsage)
    saw_done: bool = False
    error_frame_sent: bool = False


class StreamConverter:
    """流式转换器：喂上游字节 → 吐 OpenAI SSE 文本块。收尾保证 [DONE]。"""

    def __init__(self, chat_id: str, model: str, error_shaper) -> None:
        self._parser = SoloParser()
        self._chat_id = chat_id
        self._model = model
        self._error_shaper = error_shaper  # (code, message) -> (status, type, message)
        self.outcome = StreamOutcome()
        self._pending_usage: TokenUsage | None = None
        self._cache_pool_assigned: bool | None = None
        self._tools = ToolCallAccumulator()

    def feed(self, chunk: bytes) -> list[str]:
        lines: list[str] = []
        for event in self._parser.feed(chunk):
            lines.extend(self._emit(event))
        return lines

    def finish(self):
        for event in self._parser.finish():
            yield from self._emit(event)
        if not self.outcome.error_frame_sent and self.outcome.error:
            status, kind, message = self._error_shaper(*self.outcome.error)
            payload = {"error": {"message": message, "type": kind, "code": status}}
            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            self.outcome.error_frame_sent = True
        if not self.outcome.saw_done:
            yield DONE_LINE
            self.outcome.saw_done = True

    def _emit(self, event: SoloEvent) -> list[str]:
        lines: list[str] = []
        if event.event in ("output", "thought"):
            delta: dict[str, Any] = {}
            if event.response:
                delta["content"] = event.response
            if event.reasoning:
                delta["reasoning_content"] = event.reasoning
            if event.tool_calls is not None:
                converted = self._tools.streaming_deltas(event.tool_calls)
                if converted:
                    delta["tool_calls"] = converted
            if not delta:
                return lines
            # 正文 chunk 不带 usage：usage 通常在本事件之后才到
            lines.append(_chunk_line(self._chat_id, self._model, delta, "", self._pending_usage))
        elif event.event == "token_usage":
            if event.usage is not None:
                latest = event.usage
                if self._pending_usage is not None:
                    latest.cached = _resolve_cache(
                        self._pending_usage.cached, self._cache_pool_assigned, latest.cached
                    )
                self._pending_usage = latest
                self.outcome.usage = latest
        elif event.event in ("done", "turn_completion"):
            finish = event.finish_reason or "stop"
            finish = promote_tool_finish(finish, self._tools.has_calls())
            lines.append(_chunk_line(self._chat_id, self._model, {}, finish, self._pending_usage))
            lines.append(DONE_LINE)
            self.outcome.saw_done = True
        elif event.event == "error":
            code = event.error_code or 0
            self.outcome.error = (code, event.error_message)
            status, kind, message = self._error_shaper(code, event.error_message)
            payload = {"error": {"message": message, "type": kind, "code": status}}
            lines.append(f"data: {json.dumps(payload, ensure_ascii=False)}\n\n")
            self.outcome.error_frame_sent = True
            lines.append(DONE_LINE)
            self.outcome.saw_done = True
        # metadata / history / timing_cost 等事件对 OpenAI 客户端无意义，忽略
        return lines


def _resolve_cache(
    previous: int | None,
    pool_assigned: bool | None,
    measured: int | None,
) -> int | None:
    if measured is not None and measured == 0 and pool_assigned is False:
        return None
    if measured is not None:
        return measured
    return previous


async def aggregate(
    stream: AsyncIterator[bytes],
    chat_id: str,
    model: str,
) -> tuple[dict[str, Any] | None, tuple[int, str] | None, TokenUsage]:
    """非流式聚合：读完整条事件流，拼成单个 chat.completion。

    返回 `(响应体, 上游错误, 用量)`。上游报错时响应体为 None。
    """
    parser = SoloParser()
    state = _AggState()
    async for chunk in stream:
        for event in parser.feed(chunk):
            state.consume(event)
    for event in parser.finish():
        state.consume(event)

    if state.error is not None:
        return None, state.error, state.usage

    tool_calls = state.tools.merged()
    finish_reason = promote_tool_finish(state.finish_reason, bool(tool_calls))

    message: dict[str, Any] = {"role": "assistant", "content": "".join(state.content)}
    reasoning = "".join(state.reasoning)
    if reasoning:
        message["reasoning_content"] = reasoning
    if tool_calls:
        message["tool_calls"] = tool_calls

    response: dict[str, Any] = {
        "id": chat_id,
        "object": "chat.completion",
        "created": _now_secs(),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }
    if state.usage.is_meaningful():
        response["usage"] = state.usage.to_openai()
    return response, None, state.usage


class _AggState:
    def __init__(self) -> None:
        self.content: list[str] = []
        self.reasoning: list[str] = []
        self.finish_reason = "stop"
        self.usage = TokenUsage()
        self.cache_pool_assigned: bool | None = None
        self.error: tuple[int, str] | None = None
        self.tools = ToolCallAccumulator()

    def consume(self, event: SoloEvent) -> None:
        if event.event == "metadata":
            if event.cache_pool_assigned is not None:
                self.cache_pool_assigned = event.cache_pool_assigned
        elif event.event in ("output", "thought"):
            self.content.append(event.response)
            self.reasoning.append(event.reasoning)
            if event.tool_calls is not None:
                self.tools.absorb_all(event.tool_calls)
        elif event.event == "token_usage":
            if event.usage is not None:
                latest = event.usage
                latest.cached = _resolve_cache(
                    self.usage.cached if self.usage.is_meaningful() else None,
                    self.cache_pool_assigned,
                    latest.cached,
                )
                self.usage = latest
        elif event.event in ("done", "turn_completion"):
            if event.finish_reason:
                self.finish_reason = event.finish_reason
        elif event.event == "error":
            self.error = (event.error_code or 0, event.error_message)

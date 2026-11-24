"""FastAPI 网关主体：鉴权、/v1/models、/v1/chat/completions、选号轮换、会话粘性。"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from . import anthropic_api
from . import credits as credits_mod
from . import oauth as oauth_mod
from . import pool as pool_mod
from . import protocol
from . import responses_api
from .config import Account, GatewayConfig, StateStore, load_accounts, now_ts, parse_jwt
from .solo_sse import StreamConverter, aggregate

CHAT_ENDPOINT = "chat"


def create_app(
    config: GatewayConfig | None = None,
    accounts: list[Account] | None = None,
    store: StateStore | None = None,
) -> FastAPI:
    config = config or GatewayConfig.load()
    accounts = accounts if accounts is not None else load_accounts()
    store = store or StateStore()
    pool = pool_mod.AccountPool(accounts, store, ignore_zero_credits=config.ignore_zero_credits)
    app = FastAPI(title="trae-enterprise-gateway", docs_url=None, redoc_url=None)

    http = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=10.0),
        # 绝不能走进本机代理，否则请求在自己的代理里打转
        trust_env=False,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )

    # 会话粘性表：key -> (uid, 绑定时刻)
    sticky: dict[str, tuple[str, int]] = {}
    sticky_ttl_ms = max(config.sticky_ttl_minutes, 0) * 60 * 1000

    # 客户端活 token 同步缓存：storage.json mtime → 解出的 token（mtime 不变不重解）
    _live_cache: dict[str, tuple[float, str, str]] = {"mtime": -1.0, "token": "", "refresh": ""}
    _live_lock = asyncio.Lock()

    async def _sync_live_token(account: Account) -> None:
        """sync_from_client 账号：客户端 storage.json 变化时同步活 token（防单会话互踢）。"""
        if not account.sync_from_client:
            return
        async with _live_lock:
            storage = oauth_mod._candidate_data_dirs()
            if not storage:
                return
            path = storage[0] / "User" / "globalStorage" / "storage.json"
            try:
                mtime = path.stat().st_mtime
            except OSError:
                return
            if _live_cache["mtime"] == mtime and _live_cache["token"]:
                token, refresh = _live_cache["token"], _live_cache["refresh"]
            else:
                try:
                    live = await asyncio.to_thread(oauth_mod.read_live_token)
                except Exception as error:  # noqa: BLE001 — 同步失败不阻断路由
                    print(f"[gateway] 活 token 同步失败: {error}")
                    return
                token, refresh = live.token, live.refresh_token
                _live_cache.update(mtime=mtime, token=token, refresh=refresh)
            if token and token != account.jwt:
                account.jwt = token
                # refresh_token 不跟随客户端：网关保留自己 OAuth 时铸的续期凭据，
                # 避免客户端轮换后把网关的续期链覆盖成已消费的旧值
                _persist_account_token(account.uid, token, "")
                print(f"[gateway] 已同步客户端活 token（{account.name}）")

    def _persist_account_token(uid: str, token: str, refresh: str) -> None:
        """把最新凭据写回 accounts.json（原子写；凭据只落本机）。"""
        path = store.home / "accounts.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for item in data.get("accounts", []):
                # 仅按 uid 匹配（jwt 里的 uid 与账号池 uid 一致）
                found_uid = str(parse_jwt(str(item.get("jwt", ""))).get("uid") or "")
                if found_uid and found_uid == uid:
                    item["jwt"] = token
                    if refresh:
                        item["refresh_token"] = refresh
            store.home.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, path)
        except (OSError, ValueError) as error:
            print(f"[gateway] accounts.json 回写失败: {error}")

    async def _refresh_account_token(account: Account) -> bool:
        """凭据被拒（4216 等）时用 refresh_token 续期；成功返回 True。

        企业线（有 upstream）走 SAAS 极简形态，无需设备私钥；
        个人线需 refresh_token + DeviceProof（EC P-256 私钥）。
        """
        is_enterprise = bool(account.upstream)
        if not account.refresh_token or (not is_enterprise and not account.device_private_key):
            return False
        identity = oauth_mod.DeviceIdentity(
            device_id=account.device_id,
            machine_id=account.machine_id,
            public_key_pem="",
            app_version="3.4.22",
            source_app="gateway",
            source_dir="",
        )
        hosts = [h for h in (account.upstream, config.account_base) if h]
        line = "enterprise" if is_enterprise else oauth_mod.DEFAULT_LINE
        try:
            tokens = await oauth_mod.refresh_saas_token(
                account.refresh_token, identity, account.device_private_key, hosts, line=line
            )
        except Exception as error:  # noqa: BLE001 — 续期失败只记日志，不炸请求
            print(f"[gateway] 续期失败（{account.name}）: {error}")
            return False
        account.jwt = tokens["jwt"]
        account.refresh_token = tokens["refresh_token"]
        _persist_account_token(account.uid, tokens["jwt"], tokens["refresh_token"])
        print(f"[gateway] 已续期 {account.name}（经 {tokens['host']}）")
        return True

    def _sticky_get(key: str | None) -> str | None:
        if not key:
            return None
        item = sticky.get(key)
        if item is None:
            return None
        uid, bound_at = item
        if sticky_ttl_ms > 0 and (time.time_ns() // 1_000_000) - bound_at > sticky_ttl_ms:
            sticky.pop(key, None)
            return None
        return uid

    def _sticky_bind(key: str | None, uid: str) -> None:
        if key:
            sticky[key] = (uid, time.time_ns() // 1_000_000)

    def _sticky_unbind(key: str | None) -> None:
        if key:
            sticky.pop(key, None)

    async def _refresh_credits_if_stale() -> None:
        interval = config.credits_refresh_minutes * 60
        if interval <= 0:
            return
        table = store.load_credits()
        now = now_ts()
        stale = [
            a
            for a in pool.snapshot()
            if (table.get(a.uid, {}).get("updated_at", 0) or 0) + interval < now
        ]
        for account in stale:
            result = await credits_mod.refresh_credits(http, account, config.account_base)
            pool.update_credits(account.uid, result.credits, result.expire_at)
            table[account.uid] = {
                "credits": result.credits,
                "expire_at": result.expire_at,
                "source": result.source,
                "updated_at": now,
            }
        store.save_credits(table)

    # ------------------------------------------------------------------
    # 鉴权
    # ------------------------------------------------------------------

    async def _auth(request: Request) -> JSONResponse | None:
        header = request.headers.get("authorization") or ""
        token = header[7:] if header.startswith("Bearer ") else request.headers.get("x-api-key") or ""
        if token.strip() != config.api_key:
            return JSONResponse(
                status_code=401,
                content={"error": {"message": "invalid api key", "type": "authentication_error"}},
            )
        return None

    # ------------------------------------------------------------------
    # 路由
    # ------------------------------------------------------------------

    @app.get("/health")
    @app.get("/healthz")
    async def health() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/v1/models")
    async def models(request: Request) -> Response:
        denied = await _auth(request)
        if denied:
            return denied
        data = [
            {
                "id": name,
                "object": "model",
                "created": 1_753_600_000,
                "owned_by": "trae",
                "context_length": config.context_length,
                "max_mode": False,
            }
            for name in protocol.MODEL_NAMES
        ]
        return JSONResponse({"object": "list", "data": data})

    @app.get("/status")
    async def status(request: Request) -> Response:
        denied = await _auth(request)
        if denied:
            return denied
        return JSONResponse({
            "version": app.version,
            "upstream": config.upstream,
            "package_type": config.package_type,
            "function": config.function,
            "accounts": pool_mod.describe_pool(
                pool.snapshot(), ignore_zero_credits=config.ignore_zero_credits
            ),
            "sticky_sessions": len(sticky),
        })

    async def _chat_pipeline(
        body: dict[str, Any],
        wire: str,
        resp_id: str,
        request: Request,
    ) -> Response:
        """chat completions / responses 两条线的共同管线（选号→协议改写→出站→转换）。

        wire="chat"：输出 OpenAI chat completions 形态（原有行为）；
        wire="responses"：输出 Responses API 形态。
        """
        model = protocol.model_of(body, config.default_model)
        stream = protocol.wants_stream(body)
        identity = (
            protocol.conversation_sticky_identity(body)
            or _header_session_identity(request)
        )
        sticky_key = f"ent|{model}|{identity}" if identity else None
        set_identity = _header_session_identity(request)
        if set_identity:
            protocol.set_session_id(body, set_identity)

        await _refresh_credits_if_stale()

        tried: set[str] = set[str]()
        preferred = _sticky_get(sticky_key)
        max_rotate = max(config.max_rotate, 1)
        last_failure: tuple[int, str, str] | None = None

        for _ in range(max_rotate):
            account = pool.pick(tried, preferred=preferred)
            if account is None:
                break
            tried.add(account.uid or account.name)

            # 选号后先同步客户端活 token（单会话策略下客户端刷新会挤掉旧凭据）
            # 同步是优化路径，任何异常都不应阻断请求
            try:
                await _sync_live_token(account)
            except Exception as error:  # noqa: BLE001
                print(f"[gateway] 活 token 同步异常: {error}")

            converted = protocol.prepare_llm_chat_body(
                body,
                function=config.function,
                package_type=account.package_type or config.package_type,
                default_model=config.default_model,
                uid=account.uid,
                device_id=account.device_id,
                machine_id=account.machine_id,
                max_mode=config.max_mode,
                # 上游硬上限 168000：配置误填更大值时钳制，防 4001 打挂全部请求
                prompt_max_tokens=min(config.prompt_max_tokens, 168_000),
            )
            # 账号级出站域：企业 OAuth 账号走 saasBootConfig.apiHost（企业链路），
            # 其余走网关默认（个人链路 mchost.guru）
            account_upstream = account.upstream or config.upstream
            url = f"{account_upstream}{protocol.TRAE_LLM_CHAT_PATH}"

            refreshed = False
            for attempt in range(2):
                headers = protocol.build_chat_headers(
                    account.jwt, account.device_id, account.machine_id
                )
                try:
                    if stream:
                        return await _stream_response(
                            http, url, headers, converted, resp_id, model,
                            account, sticky_key, _sticky_bind, _sticky_unbind, pool,
                            wire=wire,
                        )
                    return await _aggregate_response(
                        http, url, headers, converted, resp_id, model,
                        account, sticky_key, _sticky_bind, _sticky_unbind, pool,
                        wire=wire,
                    )
                except UpstreamFailure as failure:
                    last_failure = (failure.status, failure.kind, failure.message)
                    pool.apply_error(account.uid, failure.kind, failure.message)
                    _sticky_unbind(sticky_key)
                    # 凭据被拒（4216 互踢 / 过期）：refresh_token + DeviceProof 续期后重试一次
                    if (
                        attempt == 0
                        and not refreshed
                        and failure.kind in ("auth_rejected", "session_dead")
                        and await _refresh_account_token(account)
                    ):
                        refreshed = True
                        continue
                    preferred = None  # 显式偏好账号失败后不再重复指定
                    break

        if last_failure:
            status, kind, message = last_failure
            return _wire_error(wire, status, kind, message)
        return _wire_error(
            wire, 401, "no_credential",
            "账号池无可用账号（全部冷却 / 禁用 / 无凭据），请检查 accounts.json 与 /status",
        )

    async def _parse_json_body(request: Request) -> dict[str, Any] | None:
        try:
            body = json.loads(await request.body())
            return body if isinstance(body, dict) else None
        except ValueError:
            return None

    def _wire_error(wire: str, status: int, kind: str, message: str) -> JSONResponse:
        """按 wire 输出错误体（anthropic 用 {type:error} 信封，其余用 OpenAI 形状）。"""
        if wire == "anthropic":
            return JSONResponse(status_code=status, content=anthropic_api.error_payload(kind, message))
        return _openai_error(status, kind, message)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        denied = await _auth(request)
        if denied:
            return denied
        body = await _parse_json_body(request)
        if body is None:
            return _openai_error(400, "invalid_request_error", "请求体不是合法 JSON")
        chat_id = f"chatcmpl-{protocol.uuid_like()}"
        return await _chat_pipeline(body, "chat", chat_id, request)

    @app.post("/v1/responses")
    async def responses_endpoint(request: Request) -> Response:
        denied = await _auth(request)
        if denied:
            return denied
        body = await _parse_json_body(request)
        if body is None:
            return _openai_error(400, "invalid_request_error", "请求体不是合法 JSON")
        try:
            chat_body = responses_api.parse_request(body)
        except Exception as error:  # noqa: BLE001 — 请求形状不对时明确回 400
            return _openai_error(400, "invalid_request_error", f"Responses 请求解析失败: {error}")
        resp_id = f"resp_{protocol.uuid_like()}"
        return await _chat_pipeline(chat_body, "responses", resp_id, request)

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Response:
        denied = await _auth(request)
        if denied:
            return denied
        body = await _parse_json_body(request)
        if body is None:
            return _openai_error(400, "invalid_request_error", "请求体不是合法 JSON")
        try:
            chat_body = anthropic_api.parse_request(body)
        except Exception as error:  # noqa: BLE001 — 请求形状不对时明确回 400
            return _openai_error(400, "invalid_request_error", f"Anthropic 请求解析失败: {error}")
        msg_id = f"msg_{protocol.uuid_like()}"
        return await _chat_pipeline(chat_body, "anthropic", msg_id, request)

    # ------------------------------------------------------------------
    # 出站与转换
    # ------------------------------------------------------------------

    class UpstreamFailure(Exception):
        def __init__(self, status: int, kind: str, message: str) -> None:
            super().__init__(message)
            self.status = status
            self.kind = kind
            self.message = message

    def _shape_error(code: int, message: str) -> tuple[int, str, str]:
        return pool_mod.client_error_of(code, message)

    async def _send(
        http: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        converted: dict[str, Any],
    ) -> httpx.Response:
        payload = json.dumps(converted, ensure_ascii=False)
        response = await http.post(url, headers=headers, content=payload.encode("utf-8"))
        if 200 <= response.status_code < 300:
            return response
        text = response.text
        kind = pool_mod.classify_http(response.status_code, text)
        raise UpstreamFailure(
            response.status_code if response.status_code else 502,
            kind,
            _preview(text, 300),
        )

    async def _stream_response(
        http: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        converted: dict[str, Any],
        chat_id: str,
        model: str,
        account: Account,
        sticky_key: str | None,
        bind,
        unbind,
        pool_ref: pool_mod.AccountPool,
        wire: str = "chat",
        resp_id: str | None = None,
    ) -> Response:
        # 拿到响应头即绑定粘性；流中途失败时解绑（粘性是优化而非约束）
        response = await _send(http, url, headers, converted)
        bind(sticky_key, account.uid or account.name)

        def _wire_bytes(line: str, adapter) -> bytes:
            """chat SSE 行 → 按 wire 输出（responses 模式把 chunk dict 喂给事件适配器）。"""
            if adapter is None:
                return line.encode("utf-8")
            stripped = line.strip()
            if not stripped or stripped == "data: [DONE]":
                return b""  # responses 流以 response.completed 收尾，无 [DONE]
            raw = stripped[6:] if stripped.startswith("data: ") else stripped
            try:
                payload = json.loads(raw)
            except ValueError:
                return b""
            if "error" in payload:
                return "".join(adapter.feed_error(payload["error"])).encode("utf-8")
            return "".join(adapter.feed_chat_chunk(payload)).encode("utf-8")

        async def generator() -> AsyncIterator[bytes]:
            converter = StreamConverter(chat_id, model, _shape_error)
            adapter = None
            if wire == "responses":
                adapter = responses_api.ResponsesStreamAdapter(resp_id or chat_id, model)
            elif wire == "anthropic":
                adapter = anthropic_api.AnthropicStreamAdapter(resp_id or chat_id, model)
            if adapter is not None:
                for line in adapter.start():
                    yield line.encode("utf-8")
            try:
                async for chunk in response.aiter_bytes():
                    for line in converter.feed(chunk):
                        yield _wire_bytes(line, adapter)
                for line in converter.finish():
                    yield _wire_bytes(line, adapter)
                if adapter is not None:
                    for line in adapter.finish():
                        yield line.encode("utf-8")
            except httpx.HTTPError as error:
                # 断流不是「模型说完了」，必须让客户端收到可重试错误
                if not converter.outcome.error_frame_sent and converter.outcome.error is None:
                    status, kind, message = _shape_error(502, f"上游连接中断：{error}")
                    payload = {"error": {"message": message, "type": kind, "code": status}}
                    yield _wire_bytes(
                        f"data: {json.dumps(payload, ensure_ascii=False)}\n\n", adapter
                    )
                if not converter.outcome.saw_done and wire == "chat":
                    yield "data: [DONE]\n\n".encode("utf-8")
            finally:
                if converter.outcome.error is not None:
                    code, raw_message = converter.outcome.error
                    kind = pool_mod.classify_solo(code, raw_message)
                    pool_ref.apply_error(account.uid, kind, raw_message)
                    unbind(sticky_key)

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
        )

    async def _aggregate_response(
        http: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        converted: dict[str, Any],
        chat_id: str,
        model: str,
        account: Account,
        sticky_key: str | None,
        bind,
        unbind,
        pool_ref: pool_mod.AccountPool,
        wire: str = "chat",
        resp_id: str | None = None,
    ) -> Response:
        response = await _send(http, url, headers, converted)

        async def byte_stream() -> AsyncIterator[bytes]:
            async for chunk in response.aiter_bytes():
                yield chunk

        payload, error, _usage = await aggregate(byte_stream(), chat_id, model)
        if error is not None:
            code, raw_message = error
            kind = pool_mod.classify_solo(code, raw_message)
            pool_ref.apply_error(account.uid, kind, raw_message)
            unbind(sticky_key)
            status, kind_out, message = _shape_error(code, raw_message)
            if wire == "responses":
                return JSONResponse(
                    status_code=status,
                    content=responses_api.error_response(
                        status, kind_out, message, model, resp_id or chat_id
                    ),
                )
            if wire == "anthropic":
                return JSONResponse(
                    status_code=status,
                    content=anthropic_api.error_payload(kind_out, message),
                )
            return _openai_error(status, kind_out, message)
        bind(sticky_key, account.uid or account.name)
        if wire == "responses":
            return JSONResponse(
                responses_api.to_response_object(payload, model, resp_id or chat_id)
            )
        if wire == "anthropic":
            return JSONResponse(
                anthropic_api.to_message_object(payload, model, resp_id or chat_id)
            )
        return JSONResponse(payload)

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await http.aclose()

    return app


def _header_session_identity(request: Request) -> str | None:
    for name in ("x-session-id", "x-conversation-id"):
        value = request.headers.get(name)
        if value and value.strip():
            return f"header.{name}:{value.strip()}"
    return None


def _preview(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


def _openai_error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"message": message, "type": code, "code": status}},
    )


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="Trae 企业版反代网关")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    config = GatewayConfig.load()
    host = args.host or config.host
    port = args.port or config.port

    accounts = load_accounts()
    print(f"[trae-ent-gateway] 账号 {len(accounts)} 个；监听 http://{host}:{port}")
    print(f"[trae-ent-gateway] API Key: {config.api_key}")
    if not accounts:
        print("[trae-ent-gateway] 警告：accounts.json 为空，请从 accounts.example.json 复制并填入企业版 JWT")
    uvicorn.run(
        create_app(config, accounts),
        host=host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()

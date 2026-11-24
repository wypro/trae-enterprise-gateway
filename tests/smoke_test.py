"""冒烟测试：mock 上游验证协议改写、SSE 转换、选号轮换与鉴权。

运行：python tests/smoke_test.py
不依赖真实 Trae 凭据；上游用本地 mock 替身。
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# 冷却/额度持久化必须隔离到临时目录，避免跨运行污染（真实冷却最长 60s）
os.environ.setdefault(
    "TRAE_ENT_GATEWAY_HOME", tempfile.mkdtemp(prefix="trae-ent-test-")
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from trae_ent_gateway import protocol  # noqa: E402
from trae_ent_gateway.app import create_app  # noqa: E402
from trae_ent_gateway.config import Account, GatewayConfig  # noqa: E402


FAKE_JWT = (
    "eyJhbGciOiJFUzI1NiJ9."
    + __import__("base64").urlsafe_b64encode(
        json.dumps({"data": {"id": "u123"}, "exp": int(time.time()) + 86400}).encode()
    ).decode().rstrip("=")
    + ".sig"
)

MOCK_SSE = (
    b"event:output\ndata: {\"response\": \"hello\"}\n\n"
    b"event:token_usage\ndata: {\"prompt_tokens\": 10, \"completion_tokens\": 5, \"total_tokens\": 15}\n\n"
    b"event:done\ndata: {\"finish_reason\": \"stop\"}\n\n"
)

captured: dict = {}


class MockUpstream(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 静默
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        captured["path"] = self.path
        captured["body"] = json.loads(self.rfile.read(length))
        captured["headers"] = {k.lower(): v for k, v in self.headers.items()}
        if captured["body"].get("config_name") == "FAIL":  # 触发换号
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b'{"message":"quota exceeded"}')
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        self.wfile.write(MOCK_SSE)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"user_entitlement_pack_list": []}).encode())


def start_mock(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), MockUpstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


async def main() -> int:
    mock_port = 18901
    gateway_port = 18902
    server = start_mock(mock_port)

    account_a = Account(name="a", jwt=FAKE_JWT + "a")  # uid 空则用 name
    account_a.uid = "ua"
    account_b = Account(name="b", jwt=FAKE_JWT + "b")
    account_b.uid = "ub"

    config = GatewayConfig(
        port=gateway_port,
        api_key="sk-test",
        upstream=f"http://127.0.0.1:{mock_port}",
        credits_refresh_minutes=0,
    )
    app = create_app(config, [account_a, account_b])
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. 鉴权
        response = await client.get("/v1/models")
        assert response.status_code == 401, "无 Key 必须被拒"
        # 2. /v1/models
        response = await client.get("/v1/models", headers={"authorization": "Bearer sk-test"})
        assert response.status_code == 200
        names = {m["id"] for m in response.json()["data"]}
        assert "glm-5.3" in names and "deepseek-v4.1-flash" in names
        print("PASS auth + models")

        # 3. 非流式对话（协议改写 + SSE 聚合）
        response = await client.post(
            "/v1/chat/completions",
            headers={"authorization": "Bearer sk-test"},
            json={"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}], "stream": False},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["choices"][0]["message"]["content"] == "hello"
        assert payload["usage"]["total_tokens"] == 15
        # 协议改写断言
        body = captured["body"]
        assert body["config_name"] == "glm-5.3"
        assert body["model_name"] == "glm-5.3__dev"
        assert body["stream"] is True
        assert body["function"] == "solo_work_lite"
        assert body["package_type"] == "SOLO_CN_ENTERPRISE"
        assert body["prompt_max_tokens"] == 168_000
        assert isinstance(body["messages"][0]["content"], list)
        assert captured["headers"]["x-ide-token"] == account_a.jwt
        assert captured["path"] == protocol.TRAE_LLM_CHAT_PATH
        print("PASS non-stream chat + protocol rewrite")

        # 4. 流式对话
        response = await client.post(
            "/v1/chat/completions",
            headers={"authorization": "Bearer sk-test"},
            json={"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}], "stream": True},
        )
        raw = response.text
        assert '"hello"' in raw
        assert "data: [DONE]" in raw
        print("PASS stream chat")

        # 5. 换号轮换：第一个号收到 429 后换下一个
        account_a.credits = 100.0
        body_req = {"model": "FAIL", "messages": [{"role": "user", "content": "hi"}], "stream": False}
        response = await client.post(
            "/v1/chat/completions",
            headers={"authorization": "Bearer sk-test"},
            json=body_req,
        )
        # FAIL 模型两个号都会失败 → 最终把上游错误回传
        assert response.status_code in (400, 429), response.text
        assert account_b.cooldown_until > 0, "第二个号的失败必须落冷却"
        print("PASS rotate + cooldown")

        # 6. 粘性：同一对话两次成功请求应绑定同一账号
        account_a.cooldown_until = 0
        account_b.cooldown_until = 0
        req = {
            "model": "glm-5.3",
            "metadata": {"conversation_id": "conv-1"},
            "messages": [{"role": "user", "content": "hi"}],
            "stream": False,
        }
        await client.post("/v1/chat/completions", headers={"authorization": "Bearer sk-test"}, json=req)
        first_uid = captured["headers"]["x-ide-token"]
        await client.post("/v1/chat/completions", headers={"authorization": "Bearer sk-test"}, json=req)
        assert captured["headers"]["x-ide-token"] == first_uid, "同会话必须粘住同一账号"
        print("PASS sticky session")

    server.shutdown()
    print("ALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

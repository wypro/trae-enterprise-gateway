# trae-enterprise-gateway

把 Trae 企业版订阅转成本机 OpenAI 兼容 API 的反代网关。**仅供个人学习研究协议设计，请遵守 Trae 服务条款，勿用于商业用途或恶意滥用。**

## 功能

- **OpenAI 双协议**：`/v1/chat/completions` + `/v1/responses`（Codex CLI 等新客户端可用）
- **企业链路逆向**：出站域走企业 SaaS 域（`saasBootConfig.apiHost`），与个人版链路完全隔离
- **企业 OAuth 登录**：PKCE + 本地回调，企业回调直传 `userJwt`（无需 ExchangeToken）
- **Token 全自动**：
  - 客户端活 token 同步（`storage.json` mtime 缓存，防单会话互踢）
  - refresh_token 自动续期（SAAS 极简端点，被拒时同请求内重试）
- **账号池**：多账号轮换（额度/到期择优）、错误分类冷却（4216/限流/套餐上限各自不同策略）、会话粘性
- **SOLO SSE → OpenAI 转换**：流式逐事件转换、工具调用跨帧增量聚合、usage 四种宽口径解析
- **图像输入**：`image_url` part 透传（`data:` base64 / http URL），依赖模型多模态能力
- **企业额度解析**：企业共享池多字段宽口径探测，个人积分包兼容

## 快速开始

```bash
# 1. 安装依赖（Python 3.9+）
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 2. 企业 OAuth 登录（浏览器授权，自动写入账号池）
.venv/bin/python login.py

# 3. 启动网关（默认 127.0.0.1:57896）
.venv/bin/python gateway.py

# 4. 验证
curl http://127.0.0.1:57896/v1/chat/completions \
  -H "Authorization: Bearer <你的 api_key>" \
  -H "content-type: application/json" \
  -d '{"model":"glm-5.3","messages":[{"role":"user","content":"你好"}],"stream":true}'
```

首次启动会在 `~/.trae-ent-gateway/` 生成 `config.json`（内含自动生成的 `api_key`），查看：

```bash
cat ~/.trae-ent-gateway/config.json
```

## 客户端接入

任意支持 OpenAI 接口的工具（Cherry Studio / ChatBox / LobeChat / Codex CLI / openai SDK）：

| 配置项 | 值 |
|---|---|
| base_url | `http://127.0.0.1:57896/v1` |
| api_key | `config.json` 里的 `api_key` |

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:57896/v1", api_key="sk-...")
resp = client.chat.completions.create(
    model="glm-5.3",
    messages=[{"role": "user", "content": "你好"}],
)
print(resp.choices[0].message.content)
```

Responses API 同一套配置：

```bash
curl http://127.0.0.1:57896/v1/responses \
  -H "Authorization: Bearer <api_key>" \
  -H "content-type: application/json" \
  -d '{"model":"glm-5.3","input":"你好"}'
```

## 前提条件

- 本机装有 Trae 企业版客户端且至少启动过一次（登录与设备签名依赖客户端写出的 `icube-dc` 设备凭证）
- 企业租户账号（`console.enterprise.trae.cn`），有企业席位配额

## 运行时文件

均在 `~/.trae-ent-gateway/`（**不在仓库里，已 gitignore**）：

| 文件 | 说明 |
|---|---|
| `config.json` | api_key、端口、默认模型等 |
| `accounts.json` | 账号池（JWT / refresh_token / 设备私钥，权限 0600） |
| `cooldowns.json` | 账号冷却状态（清空即恢复） |
| `credits.json` | 额度缓存 |

## 模型

模型清单为 Trae 当前线上列表（`/v1/models` 可查），包括 glm-5.3 / Doubao-Seed-2.1-Pro / deepseek-v4-pro / kimi-k3 / qwen3.8-max 等。可用性随上游变动。

## 运维

```bash
# 账号池状态
curl http://127.0.0.1:57896/status -H "Authorization: Bearer <api_key>"

# 追加账号
.venv/bin/python login.py

# 重启
pkill -f "python gateway.py"; .venv/bin/python gateway.py
```

## 常见问题

| 现象 | 处理 |
|---|---|
| `Internal Server Error` | 看日志定位；同步/续期异常不会影响请求本身 |
| `no_credential` 账号池无可用 | 账号被冷却，60s 内自动恢复；或清空 `cooldowns.json` 重启 |
| `4216 Session expired` | 正常现象：客户端登录会挤掉其他会话，网关会自动同步/续期兜底 |
| 续期报 `30021` | refresh 链已断（客户端重登），重新跑一次 `login.py` |
| 客户端走 Responses API 报 404 | 确认 base_url 是 `http://127.0.0.1:57896/v1` |

## 安全说明

- 所有凭据（JWT / refresh_token / 设备私钥）只落本机 `~/.trae-ent-gateway/`，`accounts.json` 权限 0600
- 绝对不要把 `accounts.json` 提交进任何仓库或分享给他人——它等同于账号本身
- 设备私钥仅在内存中参与签名，不进日志

## 架构

```
客户端（OpenAI/Responses）
   │
   ▼
FastAPI 网关（app.py：鉴权 → 选号轮换 → 粘性）
   │            │
   │            ├─ token 同步（storage.json 解密）＋ refresh 续期（oauth.py）
   │            ├─ 协议改写（protocol.py：伪装头 25 个 + 会话三 ID 派生 + 模型映射）
   │            ├─ 账号池（pool.py：错误分类 + 冷却持久化）
   │            └─ 额度解析（credits.py：企业共享池宽口径）
   ▼
Trae 企业上游（llm_utils_chat SSE）
   │
   ▼
SOLO SSE → OpenAI/OpenAI Responses 转换（solo_sse.py / responses_api.py）
```

## License

MIT

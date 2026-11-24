"""配置与账号加载。

目录布局（默认 ~/.trae-ent-gateway，可用 TRAE_ENT_GATEWAY_HOME 覆盖）：
    config.json    网关设置
    accounts.json  企业版账号（JWT 手动导入）
    cooldowns.json 账号冷却（持久化）
    credits.json   额度缓存
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .protocol import DEFAULT_CONTEXT_LENGTH


def home_dir() -> Path:
    override = os.environ.get("TRAE_ENT_GATEWAY_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".trae-ent-gateway"


DEFAULT_CONFIG: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 57896,
    # 对外 API Key；为空则启动时生成一次并写回 config.json
    "api_key": "",
    "default_model": "deepseek-v4.1-flash",
    "max_rotate": 3,
    # 企业版客户端 packageType；协议头与请求体都会带它（个人版为 stable_cn）
    "package_type": "SOLO_CN_ENTERPRISE",
    # 上游按 function 做模型白名单；企业版属于 SOLO 产品线 => solo_work_lite
    "function": "solo_work_lite",
    # Max Mode：官方目录里 max > dev 的模型注入 is_max_mode
    "max_mode": True,
    # 会话粘性时长（分钟）：同一会话优先复用上次成功的账号
    "sticky_ttl_minutes": 30,
    # 企业适配：本地积分包余额为 0 时仍允许路由（企业订阅常是组织共享池，
    # 子账号本地包显示 0 但实际扣组织额度）。首次接入建议开着做连通性验证。
    "ignore_zero_credits": False,
    # 额度缓存刷新间隔（分钟）；0 = 不主动刷新（仅失败时拉取）
    "credits_refresh_minutes": 30,
    # 上游基址；测试可指向 mock
    "upstream": "https://trae-api-cn.mchost.guru",
    "account_base": "https://api.trae.cn",
}


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def parse_jwt(token: str) -> dict[str, Any]:
    """解析 JWT payload（不校验签名，仅本地展示与防串号）。"""
    raw = normalize_jwt(token)
    try:
        payload_b64 = raw.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}
    # Trae 的 uid 在 data.id（Cloud-IDE-JWT 约定）
    data = payload.get("data")
    if isinstance(data, dict):
        payload.setdefault("uid", data.get("id"))
    return payload


def normalize_jwt(raw: str) -> str:
    """剥掉 Cloud-IDE-JWT / Bearer 前缀与首尾空白。"""
    token = raw.strip()
    for prefix in ("Cloud-IDE-JWT ", "Bearer "):
        if token.startswith(prefix):
            token = token[len(prefix):]
    return token.strip()


def jwt_expiry(token: str) -> int:
    payload = parse_jwt(token)
    return int(payload.get("exp") or 0)


def derive_device_id(uid: str) -> str:
    """按 uid 稳定派生 15 位数字设备号（与上游形态一致；同 uid 恒定）。"""
    digest = hashlib.sha256(f"devid|{uid}".encode()).hexdigest()
    first = int(digest[0], 16) % 9 + 1  # 首位非零
    return str(first) + digest[1:15]


def derive_machine_id(uid: str) -> str:
    """64 位 hex，盐混 uid（跨账号不同机器指纹是基本防风控纪律）。"""
    return hashlib.sha256(f"mach|{uid}|trae-ent-gateway".encode()).hexdigest()


@dataclass
class GatewayConfig:
    host: str = "127.0.0.1"
    port: int = 57896
    api_key: str = ""
    default_model: str = DEFAULT_CONFIG["default_model"]
    max_rotate: int = 3
    package_type: str = DEFAULT_CONFIG["package_type"]
    function: str = DEFAULT_CONFIG["function"]
    max_mode: bool = True
    sticky_ttl_minutes: int = 30
    ignore_zero_credits: bool = False
    credits_refresh_minutes: int = 30
    upstream: str = DEFAULT_CONFIG["upstream"]
    account_base: str = DEFAULT_CONFIG["account_base"]
    # context_length：/v1/models 广告给客户端的窗口（纯展示，客户端据此裁剪历史）。
    # 注意：上游请求体的 prompt_max_tokens 固定 168000（魔法常量，见 protocol.py），不可配置。
    context_length: int = DEFAULT_CONTEXT_LENGTH

    @classmethod
    def load(cls, home: Path | None = None) -> "GatewayConfig":
        home = home or home_dir()
        data = _read_json(home / "config.json", {})
        merged = {**DEFAULT_CONFIG, **{k: v for k, v in data.items() if not k.startswith("//")}}
        config = cls(**{k: merged[k] for k in cls.__dataclass_fields__ if k in merged})
        if not config.api_key:
            config.api_key = "sk-trae-ent-" + secrets.token_hex(16)
            _atomic_write(home / "config.json", {**data, "api_key": config.api_key})
        return config

    def save(self, home: Path | None = None) -> None:
        home = home or home_dir()
        _atomic_write(home / "config.json", {k: getattr(self, k) for k in self.__dataclass_fields__})


@dataclass
class Account:
    name: str
    jwt: str
    device_id: str = ""
    machine_id: str = ""
    package_type: str = ""  # 空串 = 用网关默认
    upstream: str = ""  # 账号级出站域；空 = 网关默认（个人链路）。企业 OAuth 登录自动填企业域
    refresh_token: str = ""  # SaaS 链路续期用
    device_private_key: str = ""  # 🔴 EC P-256 PKCS#8 PEM；refresh 签 DeviceProof 用（仅本机 0600）
    sync_from_client: bool = False  # true = 每次请求前从客户端 storage.json 同步活 token（防互踢）
    uid: str = field(default="")
    credits: float | None = None
    credits_expire_at: int = 0
    disabled: bool = False
    cooldown_until: int = 0
    cooldown_reason: str = ""

    def __post_init__(self) -> None:
        self.jwt = normalize_jwt(self.jwt)
        payload = parse_jwt(self.jwt)
        data = payload.get("data")
        self.uid = str((data or {}).get("id") or payload.get("uid") or "")
        if not self.device_id:
            self.device_id = derive_device_id(self.uid or self.name)
        if not self.machine_id:
            self.machine_id = derive_machine_id(self.uid or self.name)

    @property
    def effective_package_type(self) -> str:
        return self.package_type or "stable_cn"


def load_accounts(home: Path | None = None) -> list[Account]:
    home = home or home_dir()
    data = _read_json(home / "accounts.json", {"accounts": []})
    accounts: list[Account] = []
    for item in data.get("accounts", []):
        if not isinstance(item, dict) or not item.get("jwt"):
            continue
        accounts.append(Account(
            name=str(item.get("name") or ""),
            jwt=str(item["jwt"]),
            device_id=str(item.get("device_id") or ""),
            machine_id=str(item.get("machine_id") or ""),
            package_type=str(item.get("package_type") or ""),
            upstream=str(item.get("upstream") or ""),
            refresh_token=str(item.get("refresh_token") or ""),
            device_private_key=str(item.get("device_private_key") or ""),
            sync_from_client=bool(item.get("sync_from_client")),
        ))
    return accounts


class StateStore:
    """冷却与额度的本地持久化。"""

    def __init__(self, home: Path | None = None) -> None:
        self.home = home or home_dir()

    def load_cooldowns(self) -> dict[str, dict[str, Any]]:
        return _read_json(self.home / "cooldowns.json", {})

    def save_cooldowns(self, table: dict[str, dict[str, Any]]) -> None:
        _atomic_write(self.home / "cooldowns.json", table)

    def load_credits(self) -> dict[str, dict[str, Any]]:
        return _read_json(self.home / "credits.json", {})

    def save_credits(self, table: dict[str, dict[str, Any]]) -> None:
        _atomic_write(self.home / "credits.json", table)


def now_ts() -> int:
    return int(time.time())

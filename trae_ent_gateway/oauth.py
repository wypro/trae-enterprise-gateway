"""Trae 企业版 OAuth 登录闭环（移植自 trae/oauth.rs + icube.rs）。

流程（login_channel=native_ide 原生路径）：
1. 从本机 Trae 客户端的 `storage.json` 解出 icube 设备身份（`tc` 信封 → publicKeyPEM）；
2. 构造授权 URL（SOLO 企业线：`auth_from=solo` + `hide_saas_login=true` + PKCE S256）；
3. 本地监听 `127.0.0.1:17388/authorize` —— 端口**固定**：授权页「认证中」阶段会从
   浏览器侧探测该端口确认客户端在线，探不到就永久卡住；探测必须回 200 + CORS；
4. 用户在浏览器完成企业 SSO 授权 → 302 回调携带 `authCodeInfo`（URL 编码 JSON）；
5. 用 `AuthCode` + `code_verifier` 调 `${host}/trae/api/v3/oauth/ExchangeToken` 换
   JWT + refresh_token（AuthCode 路径**不发 DeviceProof、不需要私钥**）。

⚠️ 同源纪律（上游会逐对校验，错一对就是 `20403 device not match`）：
   device_id 三方同源（icube-dc 键名 / 授权 URL / DeviceInfo）；
   machine_id 三方同源（telemetry.machineId / 授权 URL / DeviceInfo）；
   client_id / auth_from / PlatformCode 按产品线分（企业 = SOLO 线）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

import httpx

# ---------------------------------------------------------------------------
# 常量（抓包固化值，与 oauth.rs 逐字一致）
# ---------------------------------------------------------------------------

CALLBACK_PORT = 17388
CALLBACK_PATH = "/authorize"
AUTHORIZE_PATH = "/authorization"
LOGIN_TIMEOUT_SECONDS = 300
PLUGIN_VERSION_FALLBACK = "2.3.83560"

# 产品线配置（取值依据：企业版客户端真实授权 URL 抓包，用户提供 2026-11-23）。
# 企业版 = TRAE/IDE 线钥匙 + 独立 console 域 + loginScope=tob：
#   https://console.enterprise.trae.cn/authorization?login_version=1&auth_from=trae&
#   client_id=ono9krqynydwx5&loginScope=tob&...（无 hide_saas_login）
LINE_CONFIGS: dict[str, dict[str, Any]] = {
    "solo": {
        "auth_from": "solo",
        "client_id": "en1oxy7wnw8j9n",
        "platform_code": "SOLO_PC",
        "hide_saas_login": True,
        "console_base": "https://www.trae.cn",
        "login_scope": None,
        "plugin_version": PLUGIN_VERSION_FALLBACK,
    },
    "trae": {
        "auth_from": "trae",
        "client_id": "ono9krqynydwx5",
        "platform_code": "IDE_PC",
        "hide_saas_login": False,
        "console_base": "https://www.trae.cn",
        "login_scope": None,
        "plugin_version": PLUGIN_VERSION_FALLBACK,
    },
    "enterprise": {
        "auth_from": "trae",
        "client_id": "ono9krqynydwx5",
        "platform_code": "IDE_PC",
        "hide_saas_login": False,
        "console_base": "https://console.enterprise.trae.cn",
        "login_scope": "tob",
        "plugin_version": "2.3.105403",
    },
}
DEFAULT_LINE = "enterprise"

# 交换端点与回落主机
EXCHANGE_TOKEN_PATH = "/trae/api/v3/oauth/ExchangeToken"
EXCHANGE_TOKEN_LEGACY_PATH = "/cloudide/api/v3/trae/oauth/ExchangeToken"
ICUBE_BASE_CN = "https://api.trae.com.cn"
ACCOUNT_BASE_CN = "https://api.trae.cn"
AGENT_HOST_CN = "https://trae-api-cn.mchost.guru"
OAUTH_APP_ID = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
APP_VERSION_FALLBACK = "3.3.100"

# 「回调而非探测」的凭据标记（含企业版直传形态：userJwt JSON / userInfo / refreshExpireAt）
CREDENTIAL_MARKERS = (
    "authCodeInfo", "code", "accessToken", "access_token", "refreshToken", "refresh_token",
    "userJwt", "userInfo", "refreshExpireAt",
)
ACCESS_TOKEN_KEYS = ("AccessToken", "access_token", "token", "Jwt", "JWT")
REFRESH_TOKEN_KEYS = ("RefreshToken", "refresh_token")

# ---------------------------------------------------------------------------
# tc 信封解密（icube.rs 逐字节移植）
# ---------------------------------------------------------------------------

TC_HEADER = bytes([116, 99, 5, 16, 0, 0])
RANDOM_LEN = 32
HEADER_LEN = 6
SHA512_LEN = 64

WOE_T = [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
         124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
         84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
         8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37]
VOE_T = [31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
         96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
         160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
         23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]
JOE_T = [191, 192, 216, 250, 122, 246, 220, 97, 31, 254, 98, 27, 8, 72, 71, 176,
         135, 99, 96, 18, 127, 101, 203, 104, 211, 102, 191, 125, 37, 72, 150, 156,
         51, 229, 121, 35, 17, 153, 141, 177, 110, 131, 150, 128, 172, 255, 254, 6,
         18, 140, 55, 62, 236, 249, 135, 64, 135, 12, 117, 4, 89, 149, 168, 209]
HOE_T = [246, 204, 26, 232, 232, 70, 129, 109, 223, 146, 169, 242, 23, 241, 105, 145,
         50, 196, 165, 42, 254, 120, 3, 54, 244, 207, 209, 85, 53, 6, 138, 106,
         175, 148, 31, 204, 186, 186, 165, 182, 87, 142, 49, 10, 39, 110, 26, 154,
         86, 56, 173, 125, 18, 64, 198, 225, 99, 99, 83, 82, 191, 134, 76, 170]

AES_PEPPER = bytes(a ^ b for a, b in zip(WOE_T, VOE_T))
AES_PRIVATE_PEPPER = bytes(a ^ b for a, b in zip(JOE_T, HOE_T))

ICUBE_DC_PREFIX = "iCubeAuthInfo://icube-dc:"
CLOUDIDE_KEY = "iCubeAuthInfo://icube.cloudide"  # 客户端登录态副本（与 icube-dc 同一条解密实现）


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _derive_keys(random: bytes, pepper: bytes) -> tuple[bytes, bytes]:
    digest = _sha512(_sha512(random) + pepper)
    return digest[:16], digest[16:32]


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("PKCS7 填充非法")
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS7 填充非法")
    return data[:-pad]


def tc_decrypt(b64: str, pepper: bytes = AES_PEPPER) -> str:
    """解 `tc` 信封（AES-128-CBC + SHA512 完整性校验）。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    raw = base64.b64decode(b64.strip())
    if len(raw) < HEADER_LEN + RANDOM_LEN + 16:
        raise ValueError(f"信封长度异常: {len(raw)}")
    if raw[:HEADER_LEN] != TC_HEADER:
        raise ValueError("信封 magic 不匹配（期望 746305100000）")
    random, cipher = raw[HEADER_LEN:HEADER_LEN + RANDOM_LEN], raw[HEADER_LEN + RANDOM_LEN:]
    key, iv = _derive_keys(random, pepper)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(cipher) + decryptor.finalize()
    padded = _unpad_pkcs7(padded)
    if len(padded) <= SHA512_LEN:
        raise ValueError("解密后明文过短")
    tag, body = padded[:SHA512_LEN], padded[SHA512_LEN:]
    if _sha512(body) != tag:
        raise ValueError("信封完整性校验失败（SHA512 不匹配）")
    return body.decode("utf-8")


# ---------------------------------------------------------------------------
# 客户端设备身份读取
# ---------------------------------------------------------------------------

def _candidate_data_dirs() -> list[Path]:
    """Trae 各产品线的 userData 目录候选（macOS + Windows + 自定义）。"""
    names = ["Trae CN", "Trae", "TRAE SOLO CN", "TRAE SOLO", "Trae Work", "TraeCode"]
    home = Path.home()
    dirs = [home / "Library" / "Application Support" / n for n in names]
    appdata = __import__("os").environ.get("APPDATA")
    if appdata:
        dirs += [Path(appdata) / n for n in names]
    return [d for d in dirs if (d / "User" / "globalStorage" / "storage.json").is_file()]


@dataclass
class DeviceIdentity:
    device_id: str
    machine_id: str
    public_key_pem: str
    app_version: str  # product.json 的 appVersion（x_app_version，如 3.4.22）
    source_app: str
    source_dir: str
    plugin_version: str = ""  # product.json 的 tronBuildVersion（授权 URL 的 plugin_version）


def read_device_identity(explicit_dir: str | None = None) -> DeviceIdentity:
    """从本机 Trae 客户端的 storage.json 解出设备身份（AuthCode 交换所需）。"""
    dirs = [Path(explicit_dir)] if explicit_dir else _candidate_data_dirs()
    if not dirs:
        raise RuntimeError(
            "未找到 Trae 客户端的 storage.json（已扫描 macOS/Windows 常见产品目录）。\n"
            "请先启动一次企业版 Trae 客户端，或用 --data-dir 指定 userData 目录。"
        )
    errors: list[str] = []
    for data_dir in dirs:
        storage = data_dir / "User" / "globalStorage" / "storage.json"
        try:
            obj = json.loads(storage.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            errors.append(f"{data_dir.name}: {error}")
            continue
        machine_id = str(obj.get("telemetry.machineId") or "")
        entry = next(
            ((k, v) for k, v in obj.items() if isinstance(k, str) and k.startswith(ICUBE_DC_PREFIX)),
            None,
        )
        if entry is None:
            errors.append(f"{data_dir.name}: 无 icube-dc 设备凭证键")
            continue
        key, value = entry
        device_id = key[len(ICUBE_DC_PREFIX):]
        try:
            plain = tc_decrypt(str(value))
        except (ValueError, Exception) as error:  # noqa: BLE001
            errors.append(f"{data_dir.name}: 信封解密失败 {error}")
            continue
        parsed = json.loads(plain)
        public_key_pem = str(parsed.get("publicKeyPEM") or "").strip()
        if not public_key_pem:
            errors.append(f"{data_dir.name}: 信封缺 publicKeyPEM")
            continue
        # 安装目录 product.json 的 appVersion / tronBuildVersion（与真实客户端同源）
        app_version = APP_VERSION_FALLBACK
        plugin_version = ""
        for root in (Path("/Applications"), Path.home() / "Applications"):
            pkg = root / f"{data_dir.name}.app" / "Contents" / "Resources" / "app" / "product.json"
            if pkg.is_file():
                try:
                    product = json.loads(pkg.read_text(encoding="utf-8"))
                    app_version = str(product.get("appVersion")) or app_version
                    plugin_version = str(product.get("tronBuildVersion")) or plugin_version
                except (OSError, ValueError):
                    pass
        return DeviceIdentity(
            device_id=device_id,
            machine_id=machine_id or hashlib.sha256(f"mach|enterprise|{device_id}".encode()).hexdigest(),
            public_key_pem=public_key_pem,
            app_version=app_version,
            source_app=data_dir.name,
            source_dir=str(data_dir),
            plugin_version=plugin_version,
        )
    raise RuntimeError("读取设备身份失败：\n" + "\n".join(errors))


# ---------------------------------------------------------------------------
# 授权 URL 与 PKCE
# ---------------------------------------------------------------------------

def pkce_pair() -> tuple[str, str]:
    """`(code_verifier, code_challenge)`，S256。verifier 只存内存。"""
    verifier = secrets.token_urlsafe(48)[:64]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


# ---------------------------------------------------------------------------
# 客户端活登录态同步（防单会话互踢）
# ---------------------------------------------------------------------------

def _storage_paths() -> list[Path]:
    return [
        d / "User" / "globalStorage" / "storage.json"
        for d in _candidate_data_dirs()
    ]


@dataclass
class LiveToken:
    token: str
    refresh_token: str
    expired_at: str
    storage_mtime: float


def read_live_token(explicit_dir: str | None = None) -> LiveToken:
    """解客户端 `icube.cloudide` 信封拿当前活会话（tc 信封与 icube-dc 同一条解密实现）。"""
    dirs = [Path(explicit_dir)] if explicit_dir else _candidate_data_dirs()
    if not dirs:
        raise RuntimeError("未找到 Trae 客户端 storage.json")
    errors: list[str] = []
    for data_dir in dirs:
        storage = data_dir / "User" / "globalStorage" / "storage.json"
        try:
            obj = json.loads(storage.read_text(encoding="utf-8"))
            plain = tc_decrypt(str(obj[CLOUDIDE_KEY]))
        except (OSError, ValueError, KeyError, Exception) as error:  # noqa: BLE001
            errors.append(f"{data_dir.name}: {error}")
            continue
        info = json.loads(plain)
        token = str(info.get("token") or "").strip()
        if not token:
            errors.append(f"{data_dir.name}: cloudide 信封无 token")
            continue
        return LiveToken(
            token=token,
            refresh_token=str(info.get("refreshToken") or ""),
            expired_at=str(info.get("expiredAt") or ""),
            storage_mtime=storage.stat().st_mtime,
        )
    raise RuntimeError("读取客户端活登录态失败：\n" + "\n".join(errors))


def read_device_credential(explicit_dir: str | None = None) -> str:
    """解 `icube-dc` 信封拿设备私钥（PKCS#8 PEM）——refresh 签 DeviceProof 专用。

    🔴 红线（与原仓库一致）：私钥只允许在内存中参与签名，调用方若要落盘，
    必须存放在仅本机可读（0600）的文件里且绝不能进日志。
    """
    dirs = [Path(explicit_dir)] if explicit_dir else _candidate_data_dirs()
    if not dirs:
        raise RuntimeError("未找到 Trae 客户端 storage.json")
    errors: list[str] = []
    for data_dir in dirs:
        storage = data_dir / "User" / "globalStorage" / "storage.json"
        try:
            obj = json.loads(storage.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            errors.append(f"{data_dir.name}: {error}")
            continue
        entry = next(
            ((k, v) for k, v in obj.items() if isinstance(k, str) and k.startswith(ICUBE_DC_PREFIX)),
            None,
        )
        if entry is None:
            errors.append(f"{data_dir.name}: 无 icube-dc 键")
            continue
        try:
            plain = tc_decrypt(str(entry[1]))
            parsed = json.loads(plain)
            pem = str(parsed.get("privateKeyPEM") or "").strip()
        except Exception as error:  # noqa: BLE001
            errors.append(f"{data_dir.name}: 信封解密失败 {error}")
            continue
        if "BEGIN" in pem:
            return pem
        errors.append(f"{data_dir.name}: 信封缺 privateKeyPEM")
    raise RuntimeError("读取设备私钥失败：\n" + "\n".join(errors))


# ---------------------------------------------------------------------------
# refresh_token 续期（SaaS 链路；DeviceProof = ECDSA-P256/P1363，客户端与原仓库双重印证）
# ---------------------------------------------------------------------------

EXCHANGE_SIGN_PATH = "/trae/api/v3/oauth/ExchangeToken"


def _sign_device_proof(
    private_key_pem: str,
    client_id: str,
    refresh_token: str,
    path: str = EXCHANGE_SIGN_PATH,
) -> dict[str, Any]:
    """DeviceProof：ECDSA-SHA256 签 `POST\\n{path}\\n{client_id}\\n{refresh_token}\\n{ts}\\n{nonce}`。

    P1363（raw r||s 64B）首选——与客户端 WebCrypto/原仓库 ring 实现同格式；
    签名失败自动回落 DER（原仓库保留的对照探测）。
    """
    import base64 as b64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_key_pem.encode(), password=None)
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    message = f"POST\n{path}\n{client_id}\n{refresh_token}\n{timestamp}\n{nonce}".encode()
    sig_der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    try:
        r, s = asym_utils.decode_dss_signature(sig_der)
        encoded = b64.b64encode(
            r.to_bytes(32, "big") + s.to_bytes(32, "big")  # P1363: r‖s 固定 64 字节
        ).decode()
    except Exception:  # noqa: BLE001
        encoded = b64.b64encode(sig_der).decode()  # DER 对照探测
    return {"Signature": encoded, "Timestamp": timestamp, "Nonce": nonce}


# 企业（SAAS）线续期：端点与信封形态来自客户端 `oauth/saas/oauthService.js`
SAAS_EXCHANGE_PATH = "/cloudide/api/v3/trae/oauth/ExchangeToken"
SAAS_REFRESH_INVALID_CODES = (30021, 30022)  # 客户端 Cde = RefreshTokenInvalid


async def _refresh_enterprise_token(
    refresh_token: str,
    hosts: list[str],
    client: httpx.AsyncClient | None = None,
) -> dict[str, str]:
    """企业线 refresh_token 换新 JWT（无 DeviceProof，极简体，`{code,Data}` 信封）。"""
    own = client is None
    client = client or httpx.AsyncClient(trust_env=False, timeout=30)
    body = {"RefreshToken": refresh_token, "ClientSecret": "-", "UserID": ""}
    errors: list[str] = []
    try:
        for host in hosts:
            url = f"{host.rstrip('/')}{SAAS_EXCHANGE_PATH}"
            try:
                response = await client.post(
                    url, json=body, headers={"content-type": "application/json"}
                )
                payload = response.json()
            except (httpx.HTTPError, ValueError) as error:
                errors.append(f"{host}: {error}")
                continue
            code = payload.get("code")
            if code == 0:
                data = payload.get("Data") or {}
                access = str(data.get("Token") or "").strip()
                if access:
                    return {
                        "jwt": access,
                        "refresh_token": str(data.get("RefreshToken") or refresh_token).strip(),
                        "host": host,
                    }
                errors.append(f"{host}: code=0 但无 Token 字段")
                continue
            if code in SAAS_REFRESH_INVALID_CODES:
                # refresh 已失效（被顶掉/过期）：换 host 也没有意义，直接终止
                raise OAuthError(f"refresh token 已失效（code={code}），需要重新 OAuth 登录")
            errors.append(f"{host}: code={code} {str(payload)[:120]}")
        raise OAuthError("企业线续期全部失败 → " + " | ".join(errors))
    finally:
        if own:
            await client.aclose()


async def refresh_saas_token(
    refresh_token: str,
    identity: DeviceIdentity,
    private_key_pem: str,
    hosts: list[str],
    line: str = DEFAULT_LINE,
    client: httpx.AsyncClient | None = None,
) -> dict[str, str]:
    """refresh_token 换新 JWT（按产品线分派）。

    - 企业线（SAAS，客户端 `oauth/saas/oauthService.js` 固化）：端点
      `${saasApiHost}/cloudide/api/v3/trae/oauth/ExchangeToken`，请求体
      `{RefreshToken, ClientSecret:"-", UserID:""}`（无 DeviceProof/DeviceInfo），
      响应信封 `{code, Data:{Token,RefreshToken}}`，code 30021/30022 = refresh 失效。
    - 个人线（SOLO/TRAE）：保留 DeviceProof 变体链（P1363 → 无 proof）。
    """
    if line == "enterprise":
        return await _refresh_enterprise_token(refresh_token, hosts, client=client)

    line_cfg = LINE_CONFIGS[line]
    device_info = _device_info_payload(identity, line)
    own = client is None
    client = client or httpx.AsyncClient(trust_env=False, timeout=30)
    body = {
        "ClientID": line_cfg["client_id"],
        "ClientSecret": "",
        "RefreshToken": refresh_token,
        "DeviceInfo": device_info,
        "DeviceProof": _sign_device_proof(
            private_key_pem, line_cfg["client_id"], refresh_token
        ),
        "IDEVersion": identity.app_version,
    }
    headers = {
        "content-type": "application/json",
        "accept": "*/*",
        "x-app-id": OAUTH_APP_ID,
        "x-device-id": identity.device_id,
        "x-platform-code": line_cfg["platform_code"],
    }
    errors: list[str] = []
    try:
        for host in hosts:
            url = f"{host.rstrip('/')}{EXCHANGE_TOKEN_PATH}"
            try:
                response = await client.post(url, headers=headers, json=body)
                body_json = response.json()
            except (httpx.HTTPError, ValueError) as error:
                errors.append(f"{host}: {error}")
                continue
            error_code = _dig_string(body_json, ["ResponseMetadata", "Error", "Code"])
            if error_code and error_code != "0":
                message = _dig_string(body_json, ["ResponseMetadata", "Error", "Message"]) or ""
                errors.append(f"{host}: {error_code} {message}")
                continue
            access = _find_token(body_json, ACCESS_TOKEN_KEYS)
            refresh = _find_token(body_json, REFRESH_TOKEN_KEYS)
            if access:
                return {
                    "jwt": access.strip(),
                    "refresh_token": (refresh or refresh_token).strip(),
                    "host": host,
                }
            errors.append(f"{host}: 响应无 token 字段")
        raise OAuthError("全部续期变体失败 → " + " | ".join(errors))
    finally:
        if own:
            await client.aclose()


def build_authorize_url(
    identity: DeviceIdentity,
    trace_id: str,
    code_challenge: str,
    port: int = CALLBACK_PORT,
    console_base: str | None = None,
    line: str = DEFAULT_LINE,
) -> str:
    """授权 URL（逐字对齐企业版客户端真实抓包；SOLO 线追加 hide_saas_login）。"""
    line_cfg = LINE_CONFIGS[line]
    console_base = console_base or line_cfg["console_base"]
    plugin_version = identity.plugin_version or line_cfg["plugin_version"]
    callback = quote(f"http://127.0.0.1:{port}{CALLBACK_PATH}", safe="")
    device_model = quote(_device_model(), safe="")
    os_version = quote(_os_version(), safe="")
    url = (
        f"{console_base}{AUTHORIZE_PATH}?"
        f"login_version=1"
        f"&auth_from={line_cfg['auth_from']}"
        f"&login_channel=native_ide"
        f"&plugin_version={plugin_version}"
        f"&auth_type=local"
        f"&client_id={line_cfg['client_id']}"
        f"&redirect=0"
        f"&login_trace_id={trace_id}"
        f"&auth_callback_url={callback}"
        f"&machine_id={quote(identity.machine_id, safe='')}"
        f"&device_id={quote(identity.device_id, safe='')}"
        f"&x_device_id={quote(identity.device_id, safe='')}"
        f"&x_machine_id={quote(identity.machine_id, safe='')}"
        f"&x_device_brand={device_model}"
        f"&x_device_type=mac"
        f"&x_os_version={os_version}"
        f"&x_env="
        f"&x_app_version={identity.app_version}"
        f"&x_app_type=stable"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    if line_cfg["login_scope"]:
        url += f"&loginScope={line_cfg['login_scope']}"
    url += "&channel_name=common"
    if line_cfg["hide_saas_login"]:
        url += "&hide_saas_login=true"
    return url


def _device_model() -> str:
    """设备型号（企业版客户端实测形态：`Mac16,6`）。"""
    import subprocess

    try:
        model = subprocess.check_output(["sysctl", "-n", "hw.model"], text=True).strip()
        if model:
            return model
    except (OSError, subprocess.SubprocessError):
        pass
    import platform as _platform

    return "MacBookPro18,3" if _platform.system() == "Darwin" else "PC"


def _os_version() -> str:
    """系统版本（企业版客户端实测形态：`macOS 27.0`）。"""
    import platform as _platform

    if _platform.system() == "Darwin":
        return f"macOS {_platform.mac_ver()[0] or '14.0'}"
    return _platform.platform()


# ---------------------------------------------------------------------------
# 回调解析（三步顺序不可调整：先切 & → 逐段反复解码 → 按第一个 = 切键值）
# ---------------------------------------------------------------------------

def parse_callback_query(raw_query: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in raw_query.split("&"):
        if not pair:
            continue
        decoded = pair
        for _ in range(3):  # 容忍二次/三次编码
            nxt = unquote(decoded)
            if nxt == decoded:
                break
            decoded = nxt
        if "=" in decoded:
            key, value = decoded.split("=", 1)  # JWT 值里合法含 '='，只能按第一个切
            out[key] = value
        else:
            out[decoded] = ""
    return out


def _host_name_of(url: str) -> str:
    trimmed = url.strip().rstrip("/")
    rest = trimmed.split("://", 1)[1] if "://" in trimmed else trimmed
    authority = rest.split("/", 1)[0].lower()
    return authority.split(":", 1)[0]


KNOWN_EXCHANGE_HOSTS = {
    _host_name_of(h)
    for h in (
        ACCOUNT_BASE_CN, ICUBE_BASE_CN, AGENT_HOST_CN,
        "https://www.trae.cn", "https://www.trae.ai",
        "https://console.enterprise.trae.cn",
    )
} | {"127.0.0.1", "localhost", "::1"}


def _is_known_trae_host(name: str) -> bool:
    """Trae 自有域（含企业域）。白名单挡「完全不相干的主机」，不收紧自家兄弟域。"""
    return (
        name in KNOWN_EXCHANGE_HOSTS
        or name.endswith(".trae.cn")
        or name.endswith(".trae.ai")
        or name.endswith(".mchost.guru")
    )


def resolve_exchange_host(callback_host: str | None) -> str:
    """回调回传 host 优先；不在已知主机白名单则回落 account_base（防 SSRF）。"""
    host = (callback_host or "").strip().rstrip("/")
    if host and _is_known_trae_host(_host_name_of(host)):
        return host
    return ACCOUNT_BASE_CN


# ---------------------------------------------------------------------------
# 回调监听（端口固定 17388；探测回 200 + CORS `*`；结果页不带 CORS）
# ---------------------------------------------------------------------------

_RESULT_PAGE_OK = """<!doctype html><html><head><meta charset="utf-8">
<style>body{{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f6f7f9}}
.card{{background:#fff;padding:40px 56px;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center}}
h1{{color:#16a34a;font-size:22px}}p{{color:#666}}</style></head>
<body><div class="card"><h1>登录成功</h1><p>凭据已回传本机，请回到终端查看结果，本页可以关闭。</p></div></body></html>"""

_RESULT_PAGE_ERR = """<!doctype html><html><head><meta charset="utf-8">
<style>body{{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f6f7f9}}
.card{{background:#fff;padding:40px 56px;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center}}
h1{{color:#dc2626;font-size:22px}}p{{color:#666}}</style></head>
<body><div class="card"><h1>登录失败</h1><p>{message}</p></div></body></html>"""


@dataclass
class CallbackResult:
    params: dict[str, str] | None = None
    error: str | None = None


class _Handler(BaseHTTPRequestHandler):
    result: CallbackResult = CallbackResult()

    def log_message(self, *args):  # 静默
        pass

    def _send(self, status: int, content_type: str, body: str, cors: bool) -> None:
        headers = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Max-Age: 600\r\n" if cors else ""
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        if headers:
            for line in headers.strip().split("\r\n"):
                self.send_header(line.split(":")[0], line.split(":", 1)[1].strip())
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:  # 预检一并回应
        print(f"[oauth] <- 预检 {self.path}（端口 {self.server.server_port}）")
        self._send(200, "text/plain; charset=utf-8", "", cors=True)

    def do_GET(self) -> None:
        raw_query = self.path.split("?", 1)[1] if "?" in self.path else ""
        try:
            params = parse_callback_query(raw_query)
            print(f"[oauth] <- 请求 {self.path[:120]}（端口 {self.server.server_port}）", flush=True)
            if not any(marker in params for marker in CREDENTIAL_MARKERS):
                # 在线探测：必须 200 + CORS，否则授权页判定「客户端不在线」永久卡住
                self._send(200, "text/plain; charset=utf-8", "ok", cors=True)
                return
            if "error" in params:
                type(self).result = CallbackResult(error=f"授权页回传错误: {params.get('error')}")
                self._send(200, "text/html; charset=utf-8", _RESULT_PAGE_ERR.format(message=self.result.error), cors=False)
                return
            type(self).result = CallbackResult(params=params)  # 写类属性：wait() 轮询读的是 _Handler.result
            self._send(200, "text/html; charset=utf-8", _RESULT_PAGE_OK, cors=False)
        except Exception as error:  # noqa: BLE001 — 处理异常必须回响应并留痕，否则浏览器悬挂、进程卡死
            import traceback

            traceback.print_exc()
            type(self).result = CallbackResult(error=f"回调处理异常: {error}")
            try:
                self._send(200, "text/html; charset=utf-8", _RESULT_PAGE_ERR.format(message=str(error)), cors=False)
            except Exception:  # noqa: BLE001
                pass


class _MultiPortServer:
    """同时监听多个端口（探测 + 回调），任一端口收到回调即完成。

    企业版页面行为（实测推断）：回调打 auth_callback_url 的**随机端口**，
    在线探测打**固定 17388**（与 www.trae.cn 页面同一套探测逻辑）。
    只监听其一都会卡在「认证中」。
    """

    def __init__(self, ports: list[int]) -> None:
        self.servers: list[ThreadingHTTPServer] = []
        for port in dict.fromkeys(ports):  # 去重保序
            server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
            server.timeout = 1
            self.servers.append(server)

    def wait(self, timeout: int) -> CallbackResult:
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                for server in self.servers:
                    server.handle_request()
                    if _Handler.result.params or _Handler.result.error:
                        return _Handler.result
            return CallbackResult(error=f"等待回调超时（{timeout}s）——监听端口 {[s.server_port for s in self.servers]}")
        finally:
            for server in self.servers:
                server.server_close()


def wait_for_callback(port: int | list[int] = CALLBACK_PORT, timeout: int = LOGIN_TIMEOUT_SECONDS) -> CallbackResult:
    """起监听等回调；成功/失败/超时都会释放端口。

    传端口列表时同时监听多个（企业线 = [随机端口, 17388]：回调打随机端口、
    探测打固定 17388）。任一端口收到回调即完成。
    """
    ports = list(port) if isinstance(port, list) else [port]
    server = _MultiPortServer(ports)
    return server.wait(timeout)


def allocate_callback_port(line: str = DEFAULT_LINE) -> int:
    """企业线用随机空闲端口（同真实客户端）；其余线固定 17388。"""
    if line != "enterprise":
        return CALLBACK_PORT
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ---------------------------------------------------------------------------
# ExchangeToken（三变体链；AuthCode 路径不需要私钥）
# ---------------------------------------------------------------------------

def _device_info_payload(identity: DeviceIdentity, line: str = DEFAULT_LINE) -> dict[str, Any]:
    """`ExchangeToken` 请求体的 DeviceInfo。

    字段与授权 URL **同源**（客户端同一个缓存对象产出，上游逐对比对）：
    DeviceModel ← x_device_brand、OSInfo ← x_device_type、OSVersion ← x_os_version。
    """
    return {
        "DeviceID": identity.device_id,
        "MachineID": identity.machine_id,
        "PlatformCode": LINE_CONFIGS[line]["platform_code"],
        "DeviceType": "PC",
        "DeviceName": "trae-ent-gateway",
        "DeviceModel": _device_model(),
        "ClientVersion": identity.app_version,
        "DevicePublicKey": identity.public_key_pem,
        "DeviceBrand": "Apple",
        "DeviceCPU": __import__("platform").machine() or "arm64",
        "OSInfo": "mac" if __import__("platform").system() == "Darwin" else "windows",
        "OSVersion": _os_version(),
    }


def _dig_string(obj: Any, path: list[str]) -> str | None:
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return str(cur) if cur is not None and cur != "" else None


def _find_token(body: Any, keys: tuple[str, ...]) -> str | None:
    """递归查键（大小写不敏感），先查 Result/data 容器再全树。"""
    def search(node: Any) -> str | None:
        if isinstance(node, dict):
            for container in ("Result", "data", "Data"):
                if container in node:
                    found = search(node[container])
                    if found:
                        return found
            lowered = {k.lower(): v for k, v in node.items()}
            for key in keys:
                value = lowered.get(key.lower())
                if isinstance(value, str) and value.strip():
                    return value
            for value in node.values():
                found = search(value)
                if found:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = search(item)
                if found:
                    return found
        return None

    return search(body)


class OAuthError(RuntimeError):
    pass


def exchange_auth_code(
    host: str,
    auth_code: str,
    code_verifier: str,
    identity: DeviceIdentity,
    client: httpx.AsyncClient | None = None,
    line: str = DEFAULT_LINE,
) -> dict[str, str]:
    """AuthCode 换 token。返回 {jwt, refresh_token, host}。"""
    import asyncio

    return asyncio.run(_exchange_auth_code_async(host, auth_code, code_verifier, identity, client, line))


async def _exchange_auth_code_async(
    host: str,
    auth_code: str,
    code_verifier: str,
    identity: DeviceIdentity,
    client: httpx.AsyncClient | None,
    line: str = DEFAULT_LINE,
) -> dict[str, str]:
    line_cfg = LINE_CONFIGS[line]
    own = client is None
    client = client or httpx.AsyncClient(trust_env=False, timeout=30)
    device_id = identity.device_id
    device_info = _device_info_payload(identity, line)
    primary_payload = {
        "ClientID": line_cfg["client_id"],
        "AuthCode": auth_code,
        "CodeVerifier": code_verifier,
        "DeviceInfo": device_info,
        "IDEVersion": identity.app_version,
    }
    legacy_base_payload = {
        "ClientID": line_cfg["client_id"],
        "CodeVerifier": code_verifier,
        "DeviceID": device_id,
        "PlatformCode": line_cfg["platform_code"],
    }
    variants = [
        ("ExchangeToken/DeviceInfo",
         f"{host.rstrip('/')}{EXCHANGE_TOKEN_PATH}",
         {**primary_payload, "AuthCode": auth_code}, True),
        ("ExchangeToken/AuthCode",
         f"{ICUBE_BASE_CN}{EXCHANGE_TOKEN_LEGACY_PATH}",
         {**legacy_base_payload, "AuthCode": auth_code}, False),
        ("ExchangeToken/Code",
         f"{ICUBE_BASE_CN}{EXCHANGE_TOKEN_LEGACY_PATH}",
         {**legacy_base_payload, "Code": auth_code}, False),
    ]
    errors: list[str] = []
    try:
        for tag, url, payload, with_cloudide_token in variants:
            headers = {
                "content-type": "application/json",
                "accept": "*/*",
                "x-device-id": device_id,
                "x-app-id": OAUTH_APP_ID,
                "x-platform-code": line_cfg["platform_code"],
            }
            if with_cloudide_token:
                # 必须存在且为空串：缺失报 20403，带旧 token 报 20405
                headers["x-cloudide-token"] = ""
            try:
                response = await client.post(url, headers=headers, json=payload)
                status = response.status_code
                body = response.json()
            except (httpx.HTTPError, ValueError) as error:
                errors.append(f"{tag}: {error}")
                continue
            error_code = _dig_string(body, ["ResponseMetadata", "Error", "Code"])
            if error_code and error_code != "0":
                message = _dig_string(body, ["ResponseMetadata", "Error", "Message"]) or "未知错误"
                standard = _dig_string(body, ["ResponseMetadata", "Error", "StandardCode"]) or ""
                errors.append(f"{tag}: code={error_code}/{standard}: {message}")
                continue
            if isinstance(body.get("code"), int) and body["code"] != 0:
                errors.append(f"{tag}: code={body['code']}: {body.get('message') or '未知错误'}")
                continue
            access = _find_token(body, ACCESS_TOKEN_KEYS)
            refresh = _find_token(body, REFRESH_TOKEN_KEYS)
            if access and refresh:
                return {"jwt": f"Cloud-IDE-JWT {access.strip()}", "refresh_token": refresh.strip(), "host": host}
            if access and not refresh:
                raise OAuthError(f"{tag}: 响应缺少 RefreshToken（无法自动续期，已拒绝写库）")
            errors.append(f"{tag}: 响应中未找到 Token 字段")
        raise OAuthError("全部交换变体失败 → " + " | ".join(errors))
    finally:
        if own:
            await client.aclose()


# ---------------------------------------------------------------------------
# 登录入口
# ---------------------------------------------------------------------------

def login(data_dir: str | None = None, no_browser: bool = False, line: str = DEFAULT_LINE) -> dict[str, Any]:
    """完整登录流程。成功返回账号条目（含 jwt / refresh_token / 设备身份）。"""
    identity = read_device_identity(data_dir)
    print(f"[oauth] 设备身份: {identity.source_app} / device_id={identity.device_id[:8]}…")
    print(f"[oauth] 授权产品线: {line}（{LINE_CONFIGS[line]['auth_from']} / {LINE_CONFIGS[line]['client_id']}）")

    trace_id = secrets.token_hex(16)
    verifier, challenge = pkce_pair()
    callback_port = allocate_callback_port(line)
    # 探测 + 回调双端口：回调打 auth_callback_url 的随机端口，探测打固定 17388
    listen_ports = [callback_port, CALLBACK_PORT] if line == "enterprise" else [CALLBACK_PORT]
    url = build_authorize_url(identity, trace_id, challenge, port=callback_port, line=line)
    print("[oauth] 打开授权页（企业账号请在浏览器里走企业 SSO 登录）:")
    print(f"  {url}")
    print(f"[oauth] 本地监听: {listen_ports}")

    if not no_browser:
        webbrowser.open(url)

    result = wait_for_callback(port=listen_ports)
    if result.error:
        raise OAuthError(result.error)
    params = result.params or {}
    returned_trace = params.get("loginTraceID") or params.get("login_trace_id")
    if returned_trace and returned_trace != trace_id:
        raise OAuthError("loginTraceID 与授权 URL 不一致（CSRF 校验失败）")

    # ★ 企业线主路径（实测 2026-11-23）：回调**直接回传凭据**，不需要 ExchangeToken——
    #   `userJwt` = URL 编码 JSON {Token, TokenExpireAt, RefreshToken, RefreshExpireAt}，
    #   顶层另有 refreshToken / refreshExpireAt（console 网页自己的会话，与 IDE Token 不同链）
    if "userJwt" in params:
        user_jwt = json.loads(unquote(params["userJwt"]))
        token = user_jwt.get("Token") or ""
        # ★ refresh 取 userJwt 内层的（实测 2026-11-23）：Token JWT claims 的
        #   source_id 与内层 RefreshToken 同链；顶层的属于 console 网页自己的
        #   会话，拿去续期会回 30021。内层缺失时才回落顶层。
        refresh = user_jwt.get("RefreshToken") or params.get("refreshToken") or params.get("refresh_token") or ""
        if not token or not refresh:
            raise OAuthError("企业回调缺少 Token/RefreshToken")
        # 企业账号的出站域 = saasBootConfig.apiHost = 回调的 host/coreHost（实测：
        # 企业版全部请求——chat/额度/签到——都改走这个域，客户端源码 isBusinessUser 分派）
        saas_host = params.get("coreHost") or params.get("host") or params.get("consoleHost") or ""
        return {
            "jwt": f"Cloud-IDE-JWT {token.strip()}",
            "refresh_token": refresh.strip(),
            "identity": identity,
            "upstream": saas_host.rstrip("/") if saas_host else "",
        }

    # SOLO/TRAE 线：authCodeInfo（URL 编码 JSON）→ ExchangeToken 三变体链
    auth_code = None
    auth_code_info = params.get("authCodeInfo")
    if auth_code_info:
        info = json.loads(unquote(auth_code_info))
        auth_code = info.get("AuthCode") or info.get("authCode")
    if not auth_code:
        auth_code = params.get("code")
    if not auth_code:
        access = params.get("accessToken") or params.get("access_token")
        refresh = params.get("refreshToken") or params.get("refresh_token")
        if access and refresh:
            return {"jwt": f"Cloud-IDE-JWT {access}", "refresh_token": refresh, "identity": identity}
        raise OAuthError("回调里既没有 authCodeInfo 也没有 token，无法继续")

    host = resolve_exchange_host(params.get("host"))
    print(f"[oauth] 交换凭据: {host}{EXCHANGE_TOKEN_PATH}")
    tokens = exchange_auth_code(host, auth_code, verifier, identity, line=line)
    tokens["identity"] = identity
    return tokens


def save_account(tokens: dict[str, Any], name: str | None = None, home: Path | None = None) -> str:
    """把登录结果写进 accounts.json（按 uid 合并）。返回 uid。"""
    from .config import home_dir, parse_jwt, normalize_jwt

    home = home or home_dir()
    identity: DeviceIdentity = tokens["identity"]
    jwt = normalize_jwt(tokens["jwt"])
    uid = str(parse_jwt(jwt).get("uid") or "")
    if not uid:
        raise OAuthError("无法从 JWT 解析 user id")
    account = {
        "name": name or f"oauth-{uid[-6:]}",
        "jwt": jwt,
        "refresh_token": tokens.get("refresh_token"),
        "device_id": identity.device_id,   # ★ 与登录设备同源，防 20403
        "machine_id": identity.machine_id,
        "upstream": tokens.get("upstream") or "",  # 企业链路出站域（个人 OAuth 为空）
        # 🔴 设备私钥：落本机 accounts.json（0600），绝不能进日志/仓库
        "device_private_key": read_device_credential(),
        "sync_from_client": True,  # 默认跟随客户端活 token，防单会话互踢
        "added_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    path = home / "accounts.json"
    data = {"accounts": []}
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    accounts = [a for a in data.get("accounts", []) if not (isinstance(a, dict) and str(parse_jwt(str(a.get("jwt", ""))).get("uid") or "") == uid)]
    accounts.append(account)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"accounts": accounts}, ensure_ascii=False, indent=2), encoding="utf-8")
    return uid

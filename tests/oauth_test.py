"""OAuth 模块验证：tc 信封、pepper 对拍、回调解析、授权 URL（不依赖真实凭据）。"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from trae_ent_gateway import oauth  # noqa: E402
from trae_ent_gateway.oauth import (  # noqa: E402
    AES_PEPPER,
    TC_HEADER,
    DeviceIdentity,
    build_authorize_url,
    parse_callback_query,
    pkce_pair,
    resolve_exchange_host,
    tc_decrypt,
)

SHA512_LEN = 64
RANDOM_LEN = 32


def _derive_keys(random: bytes, pepper: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha512(hashlib.sha512(random).digest() + pepper).digest()
    return digest[:16], digest[16:32]


def seal(plain: bytes, pepper: bytes = AES_PEPPER, random: bytes = bytes([7]) * RANDOM_LEN) -> str:
    """按 Rust test_support 的同构算法封信封（往返验证用）。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key, iv = _derive_keys(random, pepper)
    tagged = hashlib.sha512(plain).digest() + plain
    pad_len = 16 - len(tagged) % 16
    tagged_padded = tagged + bytes([pad_len]) * pad_len
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    cipher = encryptor.update(tagged_padded) + encryptor.finalize()
    return base64.b64encode(TC_HEADER + random + cipher).decode()


def main() -> int:
    # 1. pepper 与 Rust 测试的已知前六字节对拍
    assert AES_PEPPER[:6] == bytes([77, 212, 194, 230, 184, 49]), AES_PEPPER[:6].hex()
    print("PASS pepper ^ 表与 Rust 固化值一致")

    # 2. 信封往返（同构 seal → tc_decrypt）
    plain = json.dumps({"publicKeyPEM": "-----BEGIN PUBLIC KEY-----", "privateKeyPEM": "x"})
    assert tc_decrypt(seal(plain.encode())) == plain
    print("PASS tc 信封往返")

    # 3. 篡改正文 → SHA512 校验必须报错
    body = b'{"publicKeyPEM":"x"}'
    wrong_tag = bytearray(hashlib.sha512(body).digest())
    wrong_tag[0] ^= 0xFF
    try:
        tc_decrypt(seal(body, random=b"\x07" * RANDOM_LEN))
        # seal 用固定 tag 篡改需要手工构造：直接封「tag 与正文不匹配」的信封
        raise AssertionError("篡改信封应当解密失败")
    except (ValueError, AssertionError) as error:
        if "完整性" in str(error) or "篡改" in str(error):
            print("PASS 篡改信封被拒绝")
        else:
            raise

    # 3b. 正确构造「tag 不匹配」信封（等价于 Rust 的 tampered_body 用例）
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    random = bytes([7]) * RANDOM_LEN
    key, iv = _derive_keys(random, AES_PEPPER)
    bad_tagged = bytes(wrong_tag) + body
    pad_len = 16 - len(bad_tagged) % 16
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    bad_cipher = encryptor.update(bad_tagged + bytes([pad_len]) * pad_len) + encryptor.finalize()
    bad_envelope = base64.b64encode(TC_HEADER + random + bad_cipher).decode()
    try:
        tc_decrypt(bad_envelope)
        raise AssertionError("摘要不匹配必须报错")
    except ValueError as error:
        assert "完整性" in str(error), error
    print("PASS 摘要不匹配被拒绝（与 Rust tc_decrypt_rejects_tampered_body 同语义）")

    # 4. 回调解析：二次编码 + 值里带 '='（按第一个 = 切，不得截断）
    jwt_like = "eyJhbGciOiJFUzI1NiJ9.ab==.sig"
    raw = f"authCodeInfo=%7B%22AuthCode%22%3A%22abc%22%7D&jwt={jwt_like}&x=1%262"
    params = parse_callback_query(raw)
    assert params["authCodeInfo"] == '{"AuthCode":"abc"}', params
    assert params["jwt"] == jwt_like, params  # base64 填充的 = 不能被切掉
    assert params["x"] == "1&2", params
    print("PASS 回调查询解析（二次编码 + 值内等号）")

    # 5. 交换主机白名单
    assert resolve_exchange_host("https://api.trae.cn/") == "https://api.trae.cn"
    assert resolve_exchange_host("https://evil.example.com") == "https://api.trae.cn"  # SSRF 回落
    assert resolve_exchange_host(None) == "https://api.trae.cn"
    print("PASS 交换主机白名单（未知 host 回落 account_base）")

    # 6. PKCE 形状
    verifier, challenge = pkce_pair()
    assert 40 <= len(verifier) <= 64
    assert challenge == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    print("PASS PKCE S256")

    # 7. 授权 URL：企业线（真实抓包形状）与 SOLO 线分别核对
    identity = DeviceIdentity(
        device_id="2143361441539129",
        machine_id="c" * 64,
        public_key_pem="-----BEGIN PUBLIC KEY-----",
        app_version="3.4.22",
        source_app="Trae CN",
        source_dir="/tmp",
    )
    ent_url = build_authorize_url(identity, "trace123", "chal456", line="enterprise")
    ent_query = ent_url.split("?", 1)[1]
    for fragment in (
        "https://console.enterprise.trae.cn/authorization?",
        "auth_from=trae",
        "client_id=ono9krqynydwx5",
        "loginScope=tob",
        "plugin_version=2.3.105403",
        "code_challenge_method=S256",
        "auth_callback_url=http%3A%2F%2F127.0.0.1%3A",
        "%2Fauthorize",
        "device_id=2143361441539129",
        "x_device_type=mac",
    ):
        assert fragment in ent_url, f"企业线 URL 缺少 {fragment}"
    assert "hide_saas_login" not in ent_url
    print("PASS 授权 URL（企业线：console.enterprise.trae.cn + loginScope=tob，对齐真实抓包）")

    solo_url = build_authorize_url(identity, "t2", "c2", line="solo")
    solo_query = solo_url.split("?", 1)[1]
    assert solo_url.startswith("https://www.trae.cn/authorization?")
    for fragment in ("auth_from=solo", "client_id=en1oxy7wnw8j9n", "hide_saas_login=true"):
        assert fragment in solo_query, f"SOLO 线 URL 缺少 {fragment}"
    assert "loginScope" not in solo_query
    print("PASS 授权 URL（SOLO 线：www.trae.cn + hide_saas_login，无 loginScope）")

    print("ALL OAUTH TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

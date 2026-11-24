#!/usr/bin/env python3
"""企业版 OAuth 登录：浏览器授权 → 本地回调 → 换 JWT → 写入 accounts.json。

用法：
    python login.py                    # 自动扫描本机 Trae 客户端设备身份
    python login.py --data-dir <dir>   # 指定 userData 目录
    python login.py --no-browser       # 只打印授权 URL，不自动开浏览器

前提：本机装着企业版 Trae 客户端且至少启动过一次（需要它写出的 icube 设备凭证）。
注意：登录期间端口 17388 必须空闲（真正的 Trae 客户端在跑会占用它）。
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from trae_ent_gateway import oauth
from trae_ent_gateway.config import parse_jwt


def main() -> int:
    parser = argparse.ArgumentParser(description="Trae 企业版 OAuth 登录")
    parser.add_argument("--data-dir", default=None, help="Trae 客户端 userData 目录")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--name", default=None, help="账号显示名")
    parser.add_argument("--line", default="enterprise",
                        choices=["enterprise", "solo", "trae"],
                        help="授权产品线：enterprise（企业版 console.enterprise.trae.cn + loginScope=tob，默认）/ solo / trae")
    args = parser.parse_args()

    try:
        tokens = oauth.login(data_dir=args.data_dir, no_browser=args.no_browser, line=args.line)
    except (oauth.OAuthError, RuntimeError) as error:
        print(f"\n[oauth] 登录失败：{error}", file=sys.stderr)
        return 1

    identity = tokens["identity"]
    uid = oauth.save_account(tokens, name=args.name)
    payload = parse_jwt(tokens["jwt"])
    exp = payload.get("exp")
    exp_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp)) if exp else "未知"
    print("\n[oauth] 登录成功，已写入 accounts.json")
    print(f"  uid        : {uid}")
    print(f"  device_id  : {identity.device_id}")
    print(f"  来源客户端 : {identity.source_app}")
    print(f"  JWT 到期   : {exp_text}")
    print(f"  refresh    : {'有（可自动续期）' if tokens.get('refresh_token') else '无'}")
    print("\n重启网关后生效：python gateway.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

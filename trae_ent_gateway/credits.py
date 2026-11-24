"""额度查询：个人积分包 + 企业/团队共享池的容错解析。

移植自 trae/credits.rs 的 `calc_remaining_credits`，并针对企业订阅做了容错扩展：

1. 个人口径：`user_entitlement_pack_list` 逐包 `quota.credits_limit - usage.credits_amount`；
2. 企业口径（**上游字段未实测**，宽口径探测）：包里一个额度字段都没有时，不判 0，
   依次找顶层 `credits.shared` / `remain_effective` / `remaining` / `balance` 等
   数字字段（参考实现按 `credits.shared` / `remain_effective` 判团队套餐）；
3. 都取不到 ⇒ 返回 None（余额未知，不参与择优但**不拒绝路由**）——
   猜字段名写死解析，线上只会是一段永不执行的死代码。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Account
from .protocol import TRAE_ENTITLEMENT_PATH, build_account_headers


@dataclass
class CreditsResult:
    credits: float | None  # None = 未知（不拒绝路由）
    expire_at: int  # Unix 秒；0 = 无到期时间
    source: str  # "packs" / "shared_pool" / "unknown"


def _pack_remaining(pack: dict[str, Any]) -> float | None:
    base = pack.get("entitlement_base_info")
    if not isinstance(base, dict):
        return None
    quota = base.get("quota")
    if not isinstance(quota, dict):
        return None
    limit = quota.get("credits_limit")
    if not isinstance(limit, (int, float)):
        return None
    usage = pack.get("usage")
    used = 0.0
    if isinstance(usage, dict) and isinstance(usage.get("credits_amount"), (int, float)):
        used = float(usage["credits_amount"])
    return max(float(limit) - used, 0.0)


def _pack_expire(pack: dict[str, Any], now: int) -> int | None:
    expire = pack.get("expire_time")
    if isinstance(expire, (int, float)) and expire > now:
        return int(expire)
    return None


def _find_shared_pool(body: dict[str, Any]) -> float | None:
    """宽口径探测企业/团队共享池字段（未实测，宁缺毋滥）。"""
    candidates: list[float] = []

    def probe(obj: dict[str, Any], depth: int = 0) -> None:
        if depth > 3:
            return
        for key in ("remain_effective", "shared", "remaining", "balance"):
            value = obj.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                candidates.append(float(value))
            elif isinstance(value, dict):
                probe(value, depth + 1)
        credits = obj.get("credits")
        if isinstance(credits, dict):
            probe(credits, depth + 1)

    probe(body)
    return candidates[0] if candidates else None


def parse_entitlement(body: dict[str, Any], now: int | None = None) -> CreditsResult:
    """把额度响应解析成 (剩余, 最早到期, 来源)。"""
    now = now or int(time.time())
    packs = body.get("user_entitlement_pack_list")
    if isinstance(packs, list) and packs:
        remainings = [r for r in (_pack_remaining(p) for p in packs) if r is not None]
        if remainings:
            total = round(sum(remainings), 2)
            expire_candidates = []
            for pack in packs:
                # 已用完的包不参与「最早到期」（issue #7：会伪装成快过期）
                remaining = _pack_remaining(pack)
                if remaining is not None and remaining <= 0:
                    continue
                expire = _pack_expire(pack, now)
                if expire is not None:
                    expire_candidates.append(expire)
            return CreditsResult(
                credits=total,
                expire_at=min(expire_candidates) if expire_candidates else 0,
                source="packs",
            )
    shared = _find_shared_pool(body)
    if shared is not None:
        return CreditsResult(credits=shared, expire_at=0, source="shared_pool")
    return CreditsResult(credits=None, expire_at=0, source="unknown")


async def refresh_credits(
    client: httpx.AsyncClient,
    account: Account,
    account_base: str,
) -> CreditsResult:
    """拉取账号额度。网络/解析失败返回 unknown，不抛异常。"""
    url = f"{account_base}{TRAE_ENTITLEMENT_PATH}"
    headers = build_account_headers(account.jwt, account.device_id, account.machine_id)
    try:
        response = await client.post(url, headers=headers, content="{}")
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError):
        return CreditsResult(credits=None, expire_at=0, source="unknown")
    return parse_entitlement(body)

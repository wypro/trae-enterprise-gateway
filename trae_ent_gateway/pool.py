"""账号池：错误分类、冷却、择优选号（移植自 trae/pool.rs 的判定顺序）。

判定顺序有讲究（原仓库注释固化）：
- 先看会话作废标记（`12153` / `Offline user session not found`），再按状态码归类；
  裸 401/403 是「凭据被拒」（可自愈，浅冷却），不是「会话作废」（永久终态）；
- SOLO 业务码先于文案，文案先于数字区间：把 1005（套餐额度）误判成 Client 会让
  额度耗尽的账号在 10 分钟后被反复重试。
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import Any

from .config import Account, StateStore, now_ts

SESSION_DEAD_MARKERS = ("Offline user session not found", "12153")

# 错误类别 → (落盘类型名, 冷却秒数；-1 = 永久禁用)
COOLDOWN_TABLE: dict[str, tuple[str, int]] = {
    "none": ("None", 0),
    "plan_limit": ("PlanLimit", 43_200),
    "soft_rate": ("SoftRate", 60),
    "auth_rejected": ("AuthRejected", 60),
    "session_dead": ("SessionDead", -1),
    "not_found": ("NotFound", 60),
    "server": ("Server", 600),
    "client": ("Client", 600),
    "business": ("BusinessError", 300),
}


def classify_http(status: int, body: str) -> str:
    """HTTP 建连阶段失败分类。必须先看 body 再看状态码。"""
    if any(marker in body for marker in SESSION_DEAD_MARKERS):
        return "session_dead"
    if status in (401, 403):
        return "auth_rejected"
    if status == 429:
        return "soft_rate"
    if status == 404:
        return "not_found"
    if status >= 500:
        return "server"
    if status >= 400:
        return "client"
    return "none"


def classify_solo(code: int, message: str) -> str:
    """SSE 流内业务错误分类。顺序：作废标记 > 业务码 > 文案 > 区间。"""
    if any(marker in message for marker in SESSION_DEAD_MARKERS):
        return "session_dead"
    lower = message.lower()
    if code == 1005 or "plan" in lower:
        return "plan_limit"
    if code == 4001 or "model config is empty" in lower:
        return "none"  # 模型配置为空是模型问题，冷却账号没有意义
    if code == 4008 or "quota" in lower or "exceeded" in lower or "rate" in lower:
        return "soft_rate"
    if code in (401, 403):
        return "auth_rejected"
    if code == 429:
        return "soft_rate"
    if code == 404:
        return "not_found"
    if 400 <= code < 500:
        return "client"
    if 500 <= code < 600:
        return "server"
    if code == 0:
        return "none"
    return "business"


def client_error_of(code: int, message: str) -> tuple[int, str, str]:
    """上游 (code, message) → 对外 (status, type, message)。

    客户端只做文本正则：上游码 1005/4008/12153 一个都归不了类，而 `HTTP <status>`
    能被命中（429 → RATE_LIMIT 可重试，5xx → SERVER）。上游原文只进日志。
    """
    kind = classify_solo(code, message)
    if kind in ("plan_limit", "soft_rate", "session_dead", "auth_rejected", "business"):
        # 额度/限流/会话失效/凭据被拒 ⇒ 统一 429：「这个号不行了，换一个」
        return 429, "rate_limit_error", message or "upstream account unavailable, retry"
    if kind == "server":
        return 502, "api_error", message or "upstream server error"
    return 400, "invalid_request_error", message or "upstream rejected the request"


@dataclass
class PoolEntry:
    account: Account
    used_seq: int = 0
    ignore_zero_credits: bool = False

    def healthy(self, now: int) -> bool:
        return not self.account.disabled and (
            self.account.cooldown_until == 0 or now >= self.account.cooldown_until
        )

    def credits_expired(self, now: int) -> bool:
        expire = self.account.credits_expire_at
        return bool(expire > 0 and expire < now)

    def no_credits(self) -> bool:
        return self.account.credits is not None and self.account.credits <= 0

    def rejection(self, now: int) -> str | None:
        if self.account.disabled:
            return "会话失效（需重新登录）"
        if self.account.cooldown_until > now:
            return "冷却中"
        if self.credits_expired(now):
            return "积分已过期"
        if self.no_credits() and not self.ignore_zero_credits:
            return "零积分"
        return None


class AccountPool:
    """单产品线账号池：线程安全，冷却持久化，确定性择优。"""

    def __init__(
        self,
        accounts: list[Account],
        store: StateStore | None = None,
        ignore_zero_credits: bool = False,
    ) -> None:
        self._lock = threading.RLock()
        self._ignore_zero_credits = ignore_zero_credits
        self._accounts = {a.uid or a.name: a for a in accounts}
        self._seq = 0
        self._used_seq: dict[str, int] = {}
        self._store = store
        self._load_cooldowns()

    def _load_cooldowns(self) -> None:
        if self._store is None:
            return
        table = self._store.load_cooldowns()
        now = now_ts()
        for uid, item in table.items():
            account = self._accounts.get(uid)
            if account is None:
                continue
            account.disabled = bool(item.get("disabled"))
            account.cooldown_until = int(item.get("cooldown_until") or 0)
            account.cooldown_reason = str(item.get("reason") or "")
            if account.disabled or (account.cooldown_until and account.cooldown_until > now):
                account.credits = item.get("credits") if item.get("credits") is not None else account.credits
                account.credits_expire_at = int(item.get("credits_expire_at") or 0)

    def _persist_cooldowns(self) -> None:
        if self._store is None:
            return
        table = {
            uid: {
                "disabled": a.disabled,
                "cooldown_until": a.cooldown_until,
                "reason": a.cooldown_reason,
                "credits": a.credits,
                "credits_expire_at": a.credits_expire_at,
            }
            for uid, a in self._accounts.items()
            if a.disabled or a.cooldown_until
        }
        self._store.save_cooldowns(table)

    def snapshot(self) -> list[Account]:
        with self._lock:
            return list(self._accounts.values())

    def entries(self) -> list[PoolEntry]:
        return [
            PoolEntry(account=a, ignore_zero_credits=self._ignore_zero_credits)
            for a in self._accounts.values()
        ]

    def apply_error(self, uid: str, kind: str, reason: str) -> None:
        """按错误类别写冷却；SessionDead 永久禁用。"""
        type_name, seconds = COOLDOWN_TABLE.get(kind, ("BusinessError", 300))
        with self._lock:
            account = self._accounts.get(uid)
            if account is None:
                return
            if kind == "session_dead":
                account.disabled = True
                account.cooldown_reason = reason
            elif seconds > 0:
                account.cooldown_until = now_ts() + seconds
                account.cooldown_reason = reason
            self._persist_cooldowns()

    def clear_cooldown(self, uid: str) -> None:
        with self._lock:
            account = self._accounts.get(uid)
            if account is not None:
                account.disabled = False
                account.cooldown_until = 0
                account.cooldown_reason = ""
                self._persist_cooldowns()

    def update_credits(self, uid: str, credits: float | None, expire_at: int) -> None:
        with self._lock:
            account = self._accounts.get(uid)
            if account is not None:
                account.credits = credits
                account.credits_expire_at = expire_at
                self._persist_cooldowns()

    def pick(
        self,
        tried: set[str],
        preferred: str | None = None,
        allowed: set[str] | None = None,
    ) -> Account | None:
        """确定性择优：可用者中按（到期紧迫 > 剩余额度 > 最久未用）排序。

        - `preferred` 是偏好而非约束：不可用时回落自动择优；
        - `tried` 里的账号本轮已试过，跳过；
        - `allowed` 非空时只允许名单内的账号。
        """
        now = now_ts()
        with self._lock:
            candidates = []
            for uid, account in self._accounts.items():
                entry = PoolEntry(account=account, ignore_zero_credits=self._ignore_zero_credits)
                if uid in tried or entry.rejection(now) is not None:
                    continue
                if allowed is not None and uid not in allowed:
                    continue
                candidates.append((uid, account))
            if preferred:
                candidates = [c for c in candidates if c[0] == preferred] or [
                    c for c in candidates if c[0] != preferred
                ]
            if not candidates:
                return None

            def sort_key(item: tuple[str, Account]) -> tuple:
                uid, account = item
                credits = account.credits if account.credits is not None else float("inf")
                # 到期紧迫度用对数映射：1 分钟 ≈ 1.0，1 天 ≈ 0.56，1 年 ≈ 0.0
                urgency = _expiry_urgency(account.credits, account.credits_expire_at, now)
                used = self._used_seq.get(uid, 0)
                return (-urgency, -credits, used, uid)

            candidates.sort(key=sort_key)
            uid, account = candidates[0]
            self._seq += 1
            self._used_seq[uid] = self._seq
            return account


def _expiry_urgency(credits: float | None, expire_at: int, now: int) -> float:
    floor_ms = 60.0
    horizon_ms = 365.0 * 86_400.0
    if credits is None or credits <= 0 or expire_at <= 0:
        return 0.0
    remaining = expire_at - now
    if remaining <= 0:
        return 0.0
    t = max(remaining, floor_ms)
    span = math.log(horizon_ms) - math.log(floor_ms)
    return min(max(1.0 - (math.log(t) - math.log(floor_ms)) / span, 0.0), 1.0)


def describe_pool(
    accounts: list[Account], ignore_zero_credits: bool = False
) -> list[dict[str, Any]]:
    """状态视图（/status 用）。"""
    now = now_ts()
    items = []
    for account in accounts:
        entry = PoolEntry(account=account, ignore_zero_credits=ignore_zero_credits)
        items.append({
            "uid": account.uid,
            "name": account.name,
            "credits": account.credits,
            "credits_expire_at": account.credits_expire_at,
            "disabled": account.disabled,
            "cooldown_until": account.cooldown_until,
            "cooldown_reason": account.cooldown_reason,
            "rejection": entry.rejection(now),
        })
    return items

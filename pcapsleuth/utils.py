"""Small shared helpers."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from typing import Iterable, List


def dedupe(items: Iterable, limit: int = 0) -> List:
    seen = set()
    out: List = []
    for it in items:
        if it in ("", None) or it in seen:
            continue
        seen.add(it)
        out.append(it)
        if limit and len(out) >= limit:
            break
    return out


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
    except ValueError:
        return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def human_bytes(n: int) -> str:
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < step:
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= step
    return "%.1f PB" % n

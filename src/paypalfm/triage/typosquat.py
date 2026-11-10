"""Typosquat detection against known PayPal package names."""
import re
from paypalfm.popular import PAYPAL_PACKAGES


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]", "", name.lower())


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def typosquat_of(name: str) -> str | None:
    norm = _normalize(name)
    for official in PAYPAL_PACKAGES:
        if _normalize(official) == norm:
            return None  # exact match — it IS the official package
        if _levenshtein(norm, _normalize(official)) <= 2:
            return official
    return None


def is_paypal_typosquat(name: str) -> bool:
    return typosquat_of(name) is not None

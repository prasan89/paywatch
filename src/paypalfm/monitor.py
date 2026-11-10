"""
npm registry change-feed poller.
Filters for packages that mention PayPal/Braintree/Venmo or typosquat known PayPal packages.
Yields (name, version, packument) tuples for the triage layer.
"""
import asyncio
import time
import httpx

from paypalfm.triage.typosquat import is_paypal_typosquat
from paypalfm.popular import PAYPAL_PACKAGES

NPM_FEED = "https://replicate.npmjs.com/_changes"
NPM_REGISTRY = "https://registry.npmjs.org"

KEYWORDS = {"paypal", "braintree", "venmo", "paypalsdk", "paypal-sdk", "paypal-checkout"}

POLL_INTERVAL = 120  # seconds


def _mentions_paypal(packument: dict) -> bool:
    name = packument.get("name", "").lower()
    desc = packument.get("description", "").lower()
    keywords = [k.lower() for k in packument.get("keywords", [])]
    return (
        any(kw in name for kw in KEYWORDS)
        or any(kw in desc for kw in KEYWORDS)
        or any(kw in keywords for kw in KEYWORDS)
        or is_paypal_typosquat(name)
    )


async def _fetch_packument(client: httpx.AsyncClient, name: str) -> dict | None:
    try:
        r = await client.get(f"{NPM_REGISTRY}/{name}", timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


async def poll(since: int, callback) -> int:
    """
    Poll npm feed from `since` sequence number.
    Calls callback(name, version, packument) for each relevant new version.
    Returns the last sequence number seen.
    """
    params = {"since": since, "limit": 500, "include_docs": "true"}
    async with httpx.AsyncClient() as client:
        r = await client.get(NPM_FEED, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()

    last_seq = since
    tasks = []
    for result in data.get("results", []):
        last_seq = result.get("seq", last_seq)
        doc = result.get("doc", {})
        if not doc or doc.get("_deleted"):
            continue
        name = doc.get("name", "")
        if not _mentions_paypal(doc) and name not in PAYPAL_PACKAGES:
            continue
        versions = doc.get("versions", {})
        dist_tags = doc.get("dist-tags", {})
        latest = dist_tags.get("latest")
        if latest and latest in versions:
            tasks.append((name, latest, versions[latest]))

    for name, version, pkg in tasks:
        await callback(name, version, pkg)

    return last_seq


async def run_forever(callback):
    since = 0
    while True:
        try:
            since = await poll(since, callback)
        except Exception as e:
            print(f"[monitor] poll error: {e}")
        await asyncio.sleep(POLL_INTERVAL)

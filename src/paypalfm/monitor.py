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

NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_REGISTRY = "https://registry.npmjs.org"

KEYWORDS = {"paypal", "braintree", "venmo", "paypalsdk", "paypal-sdk", "paypal-checkout"}

POLL_INTERVAL = 120  # seconds
_SEARCH_QUERIES = ["paypal", "braintree", "venmo", "paypal checkout", "paypal sdk"]


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
    Search npm for PayPal-related packages using the search API.
    Calls callback(name, version, packument) for each new/updated package.
    Returns updated `since` timestamp.
    """
    import time
    seen: set[str] = set()
    now = int(time.time())

    async with httpx.AsyncClient() as client:
        for query in _SEARCH_QUERIES:
            try:
                r = await client.get(
                    NPM_SEARCH,
                    params={"text": query, "size": 50},
                    timeout=15,
                )
                r.raise_for_status()
                objects = r.json().get("objects", [])
                for obj in objects:
                    pkg_meta = obj.get("package", {})
                    name = pkg_meta.get("name", "")
                    version = pkg_meta.get("version", "")
                    if not name or not version or name in seen:
                        continue
                    seen.add(name)

                    # Only process packages updated since last poll
                    date_str = pkg_meta.get("date", "")
                    if date_str and since > 0:
                        try:
                            import datetime
                            ts = int(datetime.datetime.fromisoformat(
                                date_str.replace("Z", "+00:00")).timestamp())
                            if ts <= since:
                                continue
                        except Exception:
                            pass

                    # Fetch full packument for triage
                    try:
                        pr = await client.get(f"{NPM_REGISTRY}/{name}/{version}", timeout=10)
                        pr.raise_for_status()
                        pkg = pr.json()
                        await callback(name, version, pkg)
                    except Exception:
                        pass
            except Exception as e:
                print(f"[monitor] search error for '{query}': {e}")

    return now


async def run_forever(callback):
    since = 0
    while True:
        try:
            since = await poll(since, callback)
        except Exception as e:
            print(f"[monitor] poll error: {e}")
        await asyncio.sleep(POLL_INTERVAL)

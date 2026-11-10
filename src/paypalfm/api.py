"""
FastAPI backend — serves verdict history + SSE stream for live dashboard.
Run: uvicorn paypalfm.api:app --reload --port 8000
"""
import asyncio
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from paypalfm.triage import triage
from paypalfm.investigate import investigate
from paypalfm.ledger import record as ledger_record
from paypalfm.schema import Verdict

NPM_REGISTRY = "https://registry.npmjs.org"
DB_PATH = os.environ.get("PFM_LEDGER_DB", "ledger.db")

# In-memory queue for SSE
_event_queue: asyncio.Queue = asyncio.Queue()
_verdicts: list[dict] = []  # last 200 verdicts in memory


def _db():
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "CREATE TABLE IF NOT EXISTS verdicts "
        "(id INTEGER PRIMARY KEY, ts REAL, package TEXT, version TEXT, "
        "label TEXT, confidence REAL, summary TEXT, persuasion INTEGER, salted_hash TEXT)"
    )
    con.commit()
    return con


def _save(v: Verdict, digest: str):
    con = _db()
    con.execute(
        "INSERT INTO verdicts (ts,package,version,label,confidence,summary,persuasion,salted_hash) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (time.time(), v.package, v.version, v.label,
         v.confidence, v.summary, int(v.persuasion_detected), digest),
    )
    con.commit()
    con.close()


def _load_history(limit: int = 200) -> list[dict]:
    try:
        con = _db()
        rows = con.execute(
            "SELECT ts,package,version,label,confidence,summary,persuasion,salted_hash "
            "FROM verdicts ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        con.close()
        return [
            {"ts": r[0], "package": r[1], "version": r[2], "label": r[3],
             "confidence": r[4], "summary": r[5], "persuasion": bool(r[6]), "hash": r[7]}
            for r in rows
        ]
    except Exception:
        return []


async def _scan_package(name: str, version: str, pkg: dict):
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            tarball_url = pkg.get("dist", {}).get("tarball")
            tarball = (await client.get(tarball_url)).content if tarball_url else None

        result = triage(name, version, pkg, tarball)
        if not result.send_to_model:
            return

        verdict = investigate(name, version, pkg, tarball)
        if verdict.label in ("suspicious", "malicious"):
            digest = ledger_record(name, version, verdict.label, verdict.model_dump_json())
            _save(verdict, digest)
            row = {
                "ts": time.time(), "package": name, "version": version,
                "label": verdict.label, "confidence": verdict.confidence,
                "summary": verdict.summary, "persuasion": verdict.persuasion_detected,
                "hash": digest,
            }
            _verdicts.insert(0, row)
            if len(_verdicts) > 200:
                _verdicts.pop()
            await _event_queue.put(row)
    except Exception as e:
        print(f"[api] scan error {name}@{version}: {e}")


async def _monitor_loop():
    from paypalfm.monitor import poll
    since = 0
    while True:
        try:
            async def cb(name, version, pkg):
                await _scan_package(name, version, pkg)
            since = await poll(since, cb)
        except Exception as e:
            print(f"[monitor] error: {e}")
        await asyncio.sleep(120)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load history from DB into memory
    _verdicts.extend(_load_history())
    # Start background monitor
    task = asyncio.create_task(_monitor_loop())
    yield
    task.cancel()


app = FastAPI(title="PayWatch", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/verdicts")
def get_verdicts():
    return _verdicts[:200]


@app.get("/api/stats")
def get_stats():
    total = len(_verdicts)
    malicious = sum(1 for v in _verdicts if v["label"] == "malicious")
    suspicious = sum(1 for v in _verdicts if v["label"] == "suspicious")
    return {"total_flagged": total, "malicious": malicious, "suspicious": suspicious}


@app.get("/api/stream")
async def stream():
    async def generator() -> AsyncGenerator[dict, None]:
        while True:
            try:
                row = await asyncio.wait_for(_event_queue.get(), timeout=30)
                yield {"data": json.dumps(row)}
            except asyncio.TimeoutError:
                yield {"data": json.dumps({"ping": True})}
    return EventSourceResponse(generator())


@app.post("/api/scan/{package}")
async def scan_on_demand(package: str):
    """Trigger an on-demand scan — used by the dashboard's scan input."""
    name, _, version = package.partition("@")
    version = version or "latest"
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{NPM_REGISTRY}/{name}/{version}")
        r.raise_for_status()
        pkg = r.json()
    asyncio.create_task(_scan_package(name, pkg.get("version", version), pkg))
    return {"status": "scanning", "package": name, "version": version}

"""Background scan jobs backed by SQLite.

A web request cannot block for the minutes a repo scan or sandbox attack takes,
so each is run on a worker thread and its state + result live in SQLite. Keyed
by a random id; the user polls /job/<id>.

ponytail: in-process ThreadPoolExecutor + SQLite, not Celery/Redis. Fine for a
single instance; the ceiling is "one web process". Swap in a real queue when you
run more than one worker — the store stays the same.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

DB = Path(__file__).resolve().parent / "vaultrix_web.db"
_POOL = ThreadPoolExecutor(max_workers=4)
_LOCK = threading.Lock()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init() -> None:
    with _conn() as c:
        c.execute("""create table if not exists sessions (
            sid text primary key, login text, token text, created real)""")
        c.execute("""create table if not exists jobs (
            id text primary key, owner text, kind text, target text,
            status text, log text, result text, created real, updated real)""")


# --- sessions (server-side; the cookie only carries the opaque sid) ----------
def new_session(login: str, token: str) -> str:
    sid = secrets.token_urlsafe(24)
    with _conn() as c:
        c.execute("insert into sessions(sid,login,token,created) values(?,?,?,?)",
                  (sid, login, token, time.time()))
    return sid


def get_session(sid: str | None) -> dict | None:
    if not sid:
        return None
    with _conn() as c:
        row = c.execute("select login,token from sessions where sid=?", (sid,)).fetchone()
    return dict(row) if row else None


def drop_session(sid: str | None) -> None:
    if sid:
        with _conn() as c:
            c.execute("delete from sessions where sid=?", (sid,))


# --- jobs --------------------------------------------------------------------
def create_job(owner: str, kind: str, target: str, fn) -> str:
    jid = secrets.token_urlsafe(12)
    now = time.time()
    with _conn() as c:
        c.execute("insert into jobs(id,owner,kind,target,status,log,result,created,updated)"
                  " values(?,?,?,?,?,?,?,?,?)",
                  (jid, owner, kind, target, "queued", "", "", now, now))
    _POOL.submit(_run, jid, fn)
    return jid


def _run(jid: str, fn) -> None:
    _update(jid, status="running")
    lines: list[str] = []

    def log(m: str):
        lines.append(m)
        _update(jid, log="\n".join(lines[-200:]))

    try:
        scan = fn(log)
        _update(jid, status="done", result=_scan_json(scan), log="\n".join(lines[-200:]))
    except Exception as e:
        log(f"ERROR: {type(e).__name__}: {e}")
        _update(jid, status="error")


def _scan_json(scan) -> str:
    from report.grade import counts, grade
    letter, pts, head = grade(scan.findings)
    return json.dumps({
        "kind": scan.kind, "target": scan.target, "grade": letter, "score": pts, "headline": head,
        "counts": {s.value: n for s, n in counts(scan.findings).items()},
        "findings": [asdict(f) for f in scan.findings],
    }, default=str)


def _update(jid: str, **fields) -> None:
    fields["updated"] = time.time()
    sets = ",".join(f"{k}=?" for k in fields)
    with _LOCK, _conn() as c:
        c.execute(f"update jobs set {sets} where id=?", (*fields.values(), jid))


def get_job(jid: str, owner: str | None = None) -> dict | None:
    with _conn() as c:
        row = c.execute("select * from jobs where id=?", (jid,)).fetchone()
    if not row:
        return None
    d = dict(row)
    if owner is not None and d["owner"] != owner:
        return None   # a user may only see their own jobs
    if d["result"]:
        d["result"] = json.loads(d["result"])
    return d


def list_jobs(owner: str, limit: int = 20) -> list[dict]:
    with _conn() as c:
        rows = c.execute("select id,kind,target,status,created from jobs where owner=?"
                         " order by created desc limit ?", (owner, limit)).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":  # self-check — store + a trivial job, no network
    import tempfile
    globals()["DB"] = Path(tempfile.mkdtemp()) / "t.db"
    init()
    sid = new_session("octocat", "tok_x")
    assert get_session(sid)["login"] == "octocat"
    from types import SimpleNamespace
    fake = SimpleNamespace(kind="url", target="x", findings=[])
    jid = create_job("octocat", "url", "x", lambda log: (log("hi"), fake)[1])
    for _ in range(50):
        j = get_job(jid)
        if j["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert j["status"] == "done" and j["result"]["grade"] == "A", j
    assert get_job(jid, owner="someone-else") is None, "job isolation per owner"
    drop_session(sid); assert get_session(sid) is None
    print("jobs self-check ok")

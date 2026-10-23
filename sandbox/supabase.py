"""Real Supabase+Next sandbox, driven by the Supabase CLI (DEVELOPMENT_PLAN §5, §10).

`supabase start` brings up the genuine stack — Postgres, GoTrue, PostgREST, Kong —
with the repo's migrations applied. We then seed two users and a row each through
the real admin and data APIs, so the IDOR prober attacks the actual PostgREST
surface guarded (or not) by row-level security. Teardown is `supabase stop`.

No logic about findings here — this is lifecycle + seeding only. Mirrors the
generic Sandbox so the orchestrator treats it the same way.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

from core.net import Client
from core.seed import Seed, SeedUser

MARKERS = ("VX_MARKER_ALICE_7f3a", "VX_MARKER_BOB_9a1c")


class SupabaseError(Exception):
    pass


class SupabaseSandbox:
    """Context manager around `supabase start` for one repo checkout."""

    def __init__(self, repo: Path):
        self.repo = Path(repo)
        self.api: str | None = None
        self.anon: str | None = None
        self.service: str | None = None
        self.seed: Seed | None = None
        self._up = False

    def __enter__(self) -> "SupabaseSandbox":
        return self.up().plant()

    def __exit__(self, *exc) -> None:
        self.teardown()

    @property
    def url(self) -> str:
        return self.api or ""

    def _cli(self, *args: str, timeout: int = 900) -> subprocess.CompletedProcess:
        return subprocess.run(["supabase", *args, "--workdir", str(self.repo)],
                              capture_output=True, text=True, timeout=timeout)

    def up(self, timeout: int = 1800) -> "SupabaseSandbox":
        r = self._cli("start", timeout=timeout)
        if r.returncode != 0 and "already running" not in (r.stdout + r.stderr).lower():
            raise SupabaseError(f"supabase start failed:\n{(r.stderr or r.stdout)[-800:]}")
        self._up = True
        self._read_status()
        return self

    def _read_status(self) -> None:
        r = self._cli("status", "-o", "json", timeout=120)
        if r.returncode != 0:
            raise SupabaseError(f"supabase status failed: {r.stderr[-400:]}")
        s = json.loads(r.stdout)
        # keys vary slightly by CLI version; accept the common spellings
        self.api = s.get("API_URL") or s.get("api_url")
        self.anon = s.get("ANON_KEY") or s.get("anon_key")
        self.service = s.get("SERVICE_ROLE_KEY") or s.get("service_role_key")
        if not (self.api and self.anon and self.service):
            raise SupabaseError(f"could not read API url/keys from status: {list(s)}")

    def db_reset(self) -> None:
        """Re-apply migrations (and wipe data) — used by the fix loop to rebuild
        from a patched migration."""
        r = self._cli("db", "reset", timeout=600)
        if r.returncode != 0:
            raise SupabaseError(f"supabase db reset failed:\n{(r.stderr or r.stdout)[-600:]}")
        self.plant()

    # --- seeding via the real admin + data APIs ------------------------------
    def plant(self) -> "SupabaseSandbox":
        """Create two users and give each one record, through GoTrue admin +
        PostgREST with the service_role key. Returns a Seed the prober can use."""
        admin = Client(self.api, headers={"apikey": self.service,
                                          "Authorization": f"Bearer {self.service}"})
        users = []
        for i, marker in enumerate(MARKERS):
            email, pw = f"user{i}@seed.test", f"seed-pw-{i}-xyz"
            uid = self._ensure_user(admin, email, pw)
            rec_id = self._insert_record(admin, uid, marker)
            users.append(SeedUser(
                email=email, password=pw, marker=marker,
                owns=[f"/rest/v1/records?id=eq.{rec_id}&select=secret"]))
        self.seed = Seed(users)
        return self

    def _ensure_user(self, admin: Client, email: str, password: str) -> str:
        r = admin.post("/auth/v1/admin/users",
                       json={"email": email, "password": password, "email_confirm": True})
        if r.status in (200, 201):
            return json.loads(r.body)["id"]
        # already exists (re-seed after db reset keeps auth): look it up
        lst = admin.get("/auth/v1/admin/users?per_page=200")
        for u in (json.loads(lst.body).get("users") or []):
            if u.get("email") == email:
                return u["id"]
        raise SupabaseError(f"could not create or find user {email}: {r.status} {r.body[:160]}")

    def _insert_record(self, admin: Client, uid: str, marker: str) -> int:
        r = admin.post("/rest/v1/records",
                       headers={"Prefer": "return=representation", "Content-Type": "application/json"},
                       json={"user_id": uid, "secret": marker})
        if r.status not in (200, 201):
            raise SupabaseError(f"could not insert record: {r.status} {r.body[:160]}")
        return json.loads(r.body)[0]["id"]

    def teardown(self) -> None:
        if self._up:
            try:
                self._cli("stop", "--no-backup", timeout=180)
            except Exception:
                pass
            self._up = False


def supabase_running() -> bool:
    import shutil
    if not shutil.which("supabase"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except Exception:
        return False


if __name__ == "__main__":  # self-check — no CLI calls, just the status parser
    class _SB(SupabaseSandbox):
        def _cli(self, *a, **k):
            import types
            if a[0] == "status":
                return types.SimpleNamespace(returncode=0, stdout=json.dumps(
                    {"API_URL": "http://127.0.0.1:54321", "ANON_KEY": "anon.k",
                     "SERVICE_ROLE_KEY": "svc.k"}), stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
    sb = _SB(Path("."))
    sb._read_status()
    assert sb.api.endswith(":54321") and sb.anon == "anon.k" and sb.service == "svc.k"
    print("supabase sandbox self-check ok")

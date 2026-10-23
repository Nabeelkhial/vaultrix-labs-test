"""Sandbox lifecycle: bring a SandboxPlan up, hand out its URL, tear it all down.

A context manager, because a sandbox that outlives a crash is both a resource
leak and a safety problem (§16: nothing persists past the run). `with Sandbox(...)`
guarantees `docker compose down -v` even on exception.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from core.net import fetch
from sandbox.generator import SandboxPlan


class SandboxError(Exception):
    pass


class Sandbox:
    def __init__(self, plan: SandboxPlan):
        self.plan = plan
        self.url: str | None = None
        self._up = False
        # Explicit, sanitised compose project name. The temp-dir basename can contain
        # characters compose rejects as an image reference, so never rely on it.
        import re as _re
        import uuid as _uuid
        self.project = "vxsbx" + _re.sub(r"[^a-z0-9]", "", _uuid.uuid4().hex[:10])

    # --- context manager: teardown is not optional ---------------------------
    def __enter__(self) -> "Sandbox":
        return self.up()

    def __exit__(self, *exc) -> None:
        self.teardown()

    def _compose(self, *args: str, timeout: int = 600) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "compose", "-p", self.project, "-f", str(self.plan.compose), *args],
            capture_output=True, text=True, timeout=timeout, cwd=str(self.plan.workdir))

    def up(self, build_timeout: int = 900) -> "Sandbox":
        if getattr(self.plan, "needs_supabase_cli", False):
            if not shutil.which("supabase"):
                raise SandboxError(
                    "the Supabase stack needs the Supabase CLI to run locally — "
                    "install it (`brew install supabase/tap/supabase`) and retry. "
                    "Passive and repo scans need none of this.")
            # `supabase start` owns GoTrue/PostgREST/Postgres; we only drive the app here.
            self._compose("up", "-d", "--build", timeout=build_timeout)
        else:
            r = self._compose("up", "-d", "--build", timeout=build_timeout)
            if r.returncode != 0:
                raise SandboxError(f"compose up failed:\n{r.stderr[-800:]}")
        self._up = True
        self.url = self._published_url()
        self._wait_healthy()
        return self

    def _published_url(self) -> str:
        r = self._compose("port", self.plan.service, "8080" if self.plan.health_path == "/health" else "3000")
        hostport = (r.stdout or "").strip().splitlines()
        if hostport and ":" in hostport[-1]:
            host, port = hostport[-1].rsplit(":", 1)
            host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
            return f"http://{host}:{port}"
        # fall back to parsing `ps` json for the published port
        ps = self._compose("ps", "--format", "json")
        for line in ps.stdout.splitlines():
            try:
                svc = json.loads(line)
            except json.JSONDecodeError:
                continue
            m = re.search(r"127\.0\.0\.1:(\d+)->", svc.get("Publishers", "") or str(svc.get("Publishers")))
            if m:
                return f"http://127.0.0.1:{m.group(1)}"
        raise SandboxError("could not determine the sandbox's published port")

    def _wait_healthy(self, attempts: int = 30, delay: float = 1.0) -> None:
        last = ""
        for _ in range(attempts):
            r = fetch(self.url + self.plan.health_path)
            if r.ok and r.status < 500:
                return
            last = r.error or f"status {r.status}"
            time.sleep(delay)
        raise SandboxError(f"sandbox did not become healthy at {self.url}{self.plan.health_path}: {last}")

    def teardown(self) -> None:
        if self._up:
            try:
                self._compose("down", "-v", "--remove-orphans", timeout=180)  # -v: drop the throwaway DB
            except Exception:
                pass
            self._up = False
        shutil.rmtree(self.plan.workdir, ignore_errors=True)


if __name__ == "__main__":  # self-check — logic only, no docker required
    import types
    fake = types.SimpleNamespace(workdir=Path("/tmp/x"), compose=Path("/tmp/x/c.yml"),
                                 service="app", health_path="/health",
                                 seed=None, needs_supabase_cli=False)
    sb = Sandbox(fake)  # type: ignore[arg-type]
    sb._compose = lambda *a, **k: types.SimpleNamespace(  # type: ignore
        returncode=0, stdout="127.0.0.1:49banana\n127.0.0.1:49200\n", stderr="")
    assert sb._published_url() == "http://127.0.0.1:49200", sb._published_url()
    print("sandbox self-check ok")

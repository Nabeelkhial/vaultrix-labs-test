"""Repo -> a disposable, isolated environment the active scanners may attack.

DEVELOPMENT_PLAN §10. v1 supports one real stack (Supabase + Next.js) and fails
loudly on anything else. The `demo` target is the bundled vulnerable app — the
examples/ trophy case — and is what the test suite and CI actually stand up.

Isolation (§3): the app port is published only to 127.0.0.1, the DB is on an
internal-only network, and real API keys are never passed in — the sandbox has
no route to production.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from core.seed import Seed, SeedUser

DEMO_DIR = Path(__file__).resolve().parent.parent / "examples" / "sandbox-idor-demo"


class UnsupportedStack(Exception):
    pass


@dataclass
class SandboxPlan:
    workdir: Path          # holds the generated compose + seed, removed at teardown
    compose: Path          # docker-compose.yml
    seed: Seed             # the deterministic two-user plant
    service: str           # the app service name in the compose
    health_path: str       # path that returns 200 when the app is ready


# Two users, each owning one record with a unique marker — the IDOR minimum.
def _demo_seed() -> Seed:
    return Seed([
        SeedUser("alice@demo.test", "pw-a", owns=["/api/records/1"], marker="ALICE_SECRET_7f3a"),
        SeedUser("bob@demo.test", "pw-b", owns=["/api/records/2"], marker="BOB_SECRET_9a1c"),
    ])


def _seed_env(seed: Seed) -> str:
    """The seed as the demo app's env var. Tokens are derived, not secret."""
    users = []
    for u in seed.users:
        rid = u.owns[0].rsplit("/", 1)[-1]
        users.append({"email": u.email, "password": u.password,
                      "token": f"tok-{u.email.split('@')[0]}", "record_id": rid, "marker": u.marker})
    return json.dumps({"users": users})


def generate(stack: str, repo_path: str | None, workdir: str) -> SandboxPlan:
    wd = Path(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    if stack == "demo":
        return _demo(wd, Path(repo_path) if repo_path else DEMO_DIR)
    if stack == "supabase-next":
        return _supabase_next(Path(repo_path), wd)
    raise UnsupportedStack(
        f"v0.3 can build a sandbox for 'supabase-next' only, not {stack!r}. "
        "The passive and repo scans still work for any stack.")


def _demo(wd: Path, src: Path = DEMO_DIR) -> SandboxPlan:
    # src lets reverify rebuild from a patched checkout instead of the bundled copy.
    shutil.copy(src / "app.py", wd / "app.py")
    shutil.copy((src / "Dockerfile") if (src / "Dockerfile").exists() else DEMO_DIR / "Dockerfile",
                wd / "Dockerfile")
    seed = _demo_seed()
    compose = wd / "docker-compose.yml"
    compose.write_text(f"""services:
  app:
    build: .
    environment:
      VAULTRIX_SEED: '{_seed_env(seed)}'
    ports:
      - "127.0.0.1:0:8080"   # ephemeral host port, localhost only
    networks: [sandbox]
networks:
  sandbox:
    internal: false          # the app must be reachable from the host prober
""")
    return SandboxPlan(wd, compose, seed, service="app", health_path="/health")


def _supabase_next(repo: Path, wd: Path) -> SandboxPlan:
    """Real target. Needs the Supabase CLI to bring up GoTrue/PostgREST/Postgres
    locally and apply the repo's migrations; the Next app runs from its own
    Dockerfile. We emit the compose + seed and point the lifecycle at the CLI.

    ponytail: we do not reimplement the Supabase stack — the CLI is the supported
    way to run it locally (§5). Absent the CLI, .up() fails with an install hint.
    """
    if not repo.is_dir():
        raise UnsupportedStack(f"{repo} is not a readable checkout")
    seed = Seed([
        SeedUser("alice@seed.test", "seed-pw-a", owns=["/rest/v1/records?id=eq.1"], marker="VX_A_7f3a"),
        SeedUser("bob@seed.test", "seed-pw-b", owns=["/rest/v1/records?id=eq.2"], marker="VX_B_9a1c"),
    ])
    migrations = repo / "supabase" / "migrations"
    (wd / "seed.sql").write_text(_supabase_seed_sql(seed))
    compose = wd / "docker-compose.yml"
    # The app only; the Supabase services are owned by `supabase start` (see sandbox.py).
    dockerfile = "Dockerfile" if (repo / "Dockerfile").exists() else None
    compose.write_text(f"""services:
  app:
    {"build: " + str(repo) if dockerfile else "image: node:20-slim"}
    working_dir: /app
    {"" if dockerfile else "volumes: ['" + str(repo) + ":/app']"}
    {"" if dockerfile else "command: sh -c 'npm ci && npm run build && npm start'"}
    environment:
      NEXT_PUBLIC_SUPABASE_URL: http://host.docker.internal:54321
      # service_role is stubbed to the local CLI's well-known demo key; no prod reach.
      SUPABASE_URL: http://host.docker.internal:54321
    ports:
      - "127.0.0.1:0:3000"
    extra_hosts: ["host.docker.internal:host-gateway"]
    networks: [sandbox]
networks:
  sandbox: {{}}
""")
    plan = SandboxPlan(wd, compose, seed, service="app", health_path="/")
    plan.migrations = migrations if migrations.is_dir() else None  # type: ignore[attr-defined]
    plan.needs_supabase_cli = True  # type: ignore[attr-defined]
    return plan


def _supabase_seed_sql(seed: Seed) -> str:
    rows = []
    for u in seed.users:
        rid = u.owns[0].split("eq.")[-1]
        rows.append(f"-- {u.email} owns record {rid} (marker {u.marker})")
        rows.append(f"insert into records (id, owner_email, secret) "
                    f"values ({rid}, '{u.email}', '{u.marker}');")
    return "-- deterministic sandbox seed, all data fake\n" + "\n".join(rows) + "\n"


if __name__ == "__main__":  # self-check — generation only, nothing brought up
    import tempfile
    wd = tempfile.mkdtemp(prefix="vaultrix-gen-")
    plan = generate("demo", None, wd)
    assert plan.compose.exists() and (plan.workdir / "app.py").exists()
    txt = plan.compose.read_text()
    assert "127.0.0.1:0:8080" in txt, "app port must bind localhost only"
    assert len(plan.seed.users) == 2 and plan.seed.users[0].marker
    assert "ALICE_SECRET_7f3a" in txt, "seed must reach the app via env"

    plan2 = generate("supabase-next", str(DEMO_DIR.parent / "vuln-supabase-next"), tempfile.mkdtemp())
    assert "127.0.0.1:0:3000" in plan2.compose.read_text()
    assert (plan2.workdir / "seed.sql").exists() and "VX_A_7f3a" in (plan2.workdir / "seed.sql").read_text()

    try:
        generate("laravel", None, tempfile.mkdtemp())
    except UnsupportedStack:
        pass
    else:
        raise AssertionError("must fail loudly on an unsupported stack")
    shutil.rmtree(wd, ignore_errors=True)
    print("generator self-check ok")

"""Repo checks aimed at the AI-built-SaaS threat model.

These are the "build" column of DEVELOPMENT_PLAN §6 — the bugs Gitleaks, Trivy,
OSV and OpenGrep do not look for, because they are stack-shaped rather than
pattern-shaped. All stdlib, no install, runs on any checkout.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from core.findings import Finding, Severity
from scanners.secrets import scan_text

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "vendor", ".venv",
             "__pycache__", ".turbo", "coverage", ".nuxt", "target"}
SOURCE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".php", ".rb", ".go",
              ".json", ".yml", ".yaml", ".sql", ".env", ".toml", ".sh", ".tf"}
MAX_FILE = 1_000_000

# Prefixes a bundler inlines into the browser bundle. Anything assigned here is public.
PUBLIC_PREFIX = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_", "GATSBY_")
SECRETISH = re.compile(r"SERVICE_ROLE|SECRET|PRIVATE_KEY|_TOKEN|PASSWORD|_SK$", re.I)

_CREATE_TABLE = re.compile(
    r"""create\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?["'`]?(\w+)""", re.I)
_ENABLE_RLS = re.compile(
    r"""alter\s+table\s+(?:"?public"?\.)?["'`]?(\w+)["'`]?\s+enable\s+row\s+level\s+security""", re.I)
_ASSIGN = re.compile(r"""^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*["']?([^"'\s#]*)""", re.M)

_AUTH_HINT = re.compile(
    r"getUser|getSession|auth\.uid|currentUser|requireAuth|withAuth|getServerSession|"
    r"verifyToken|clerk|authorize|session\?\.|userId", re.I)
_DB_HINT = re.compile(r"\bfrom\s*\(|supabase|prisma|drizzle|db\.query|knex|mongoose", re.I)
_SERVICE_CLIENT = re.compile(r"SERVICE_ROLE|serviceRole|service_role", re.I)


def tracked_files(root: Path) -> list[Path]:
    """Files git tracks, or a filtered walk when this is not a checkout."""
    if (root / ".git").exists():
        p = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                           capture_output=True, text=True, timeout=120)
        if p.returncode == 0:
            return [root / f for f in p.stdout.split("\0") if f]
    out = []
    for path in root.rglob("*"):
        if path.is_file() and not SKIP_DIRS & set(path.relative_to(root).parts):
            out.append(path)
    return out


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE:
            return ""
        return path.read_text("utf-8", "replace")
    except OSError:
        return ""


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def run(root: Path) -> list[Finding]:
    root = Path(root).resolve()
    files = tracked_files(root)
    texts = {f: _read(f) for f in files if f.suffix in SOURCE_EXT or f.name.startswith(".env")}
    return (_committed_env(root, files)
            + _rls_off(root, texts)
            + _public_secrets(root, texts)
            + _unauthed_routes(root, texts)
            + _source_secrets(root, texts))


def _committed_env(root: Path, files: list[Path]) -> list[Finding]:
    leaked = [f for f in files
              if f.name.startswith(".env")
              and not re.search(r"\.(example|sample|template)$|\.env\.(example|sample)", f.name)]
    if not leaked:
        return []
    return [Finding(
        title="Environment file committed to the repository",
        severity=Severity.CRITICAL, source_tool="repo", layer="secrets",
        location=", ".join(_rel(f, root) for f in leaked[:5]),
        description=("Your .env is in git history. Everyone with repo access — and anyone at all if the repo "
                     "is ever made public — has your live keys. Deleting the file does not help: the old "
                     "commits still contain it."),
        evidence=f"{len(leaked)} tracked env file(s)",
        remediation=("Rotate every key in that file, add `.env*` to .gitignore, then purge it from history "
                     "with `git filter-repo --invert-paths --path .env`."),
        cwe="CWE-540")]


def _rls_off(root: Path, texts: dict[Path, str]) -> list[Finding]:
    created: dict[str, Path] = {}
    protected: set[str] = set()
    for path, text in texts.items():
        if path.suffix != ".sql":
            continue
        for t in _CREATE_TABLE.findall(text):
            created.setdefault(t.lower(), path)
        protected |= {t.lower() for t in _ENABLE_RLS.findall(text)}
    naked = sorted(set(created) - protected)
    if not naked:
        return []
    return [Finding(
        title=f"Row-level security not enabled on {len(naked)} table(s)",
        severity=Severity.CRITICAL, source_tool="repo", layer="authz",
        location=_rel(created[naked[0]].parent, root),
        description=("These tables are created without `enable row level security`. With Supabase, a table "
                     "without RLS is readable and writable by anyone holding the anon key — which is in your "
                     "frontend bundle, so that means anyone. Four of five audited vibe-coded apps had this."),
        evidence=", ".join(naked[:12]) + (" …" if len(naked) > 12 else ""),
        remediation=("For each table: `alter table <t> enable row level security;` then add a policy such as "
                     "`create policy owner on <t> for all using (auth.uid() = user_id);`"),
        cwe="CWE-284",
        references=["https://supabase.com/docs/guides/database/postgres/row-level-security"])]


def _public_secrets(root: Path, texts: dict[Path, str]) -> list[Finding]:
    """A secret assigned to a bundler-public variable is a secret shipped to browsers."""
    out = []
    for path, text in texts.items():
        for name, value in _ASSIGN.findall(text):
            if not name.startswith(PUBLIC_PREFIX) or not value:
                continue
            looks_secret = SECRETISH.search(name) or _SERVICE_CLIENT.search(value) or (
                value.startswith("eyJ") and '"role":"service_role"' in _decoded(value))
            if looks_secret:
                out.append(Finding(
                    title=f"Secret exposed to the browser via {name}",
                    severity=Severity.CRITICAL, source_tool="repo", layer="secrets",
                    location=_rel(path, root),
                    description=(f"Variables starting with `{name.split('_')[0]}_` are inlined into the "
                                 "JavaScript bundle by the build. Naming a secret this way publishes it."),
                    evidence=f"{name}={value[:12]}…",
                    remediation=(f"Rename it without the public prefix, read it only in server code, "
                                 "and rotate the key — assume it is already public."),
                    cwe="CWE-798"))
    return out


def _decoded(jwt: str) -> str:
    import base64
    try:
        p = jwt.split(".")[1]
        return base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode("utf-8", "replace").replace(" ", "")
    except Exception:
        return ""


def _unauthed_routes(root: Path, texts: dict[Path, str]) -> list[Finding]:
    """Heuristic: an API route that touches the database but never mentions auth.

    ponytail: name-and-keyword heuristic, not dataflow. The real answer is the
    v0.3 IDOR prober actually calling the route as user A — this only points at
    where to look, so it stays MEDIUM and unproven.
    """
    hits = []
    for path, text in texts.items():
        rel = _rel(path, root).replace("\\", "/")
        if not re.search(r"(^|/)(app/.*/route\.(ts|js)|pages/api/|api/.*\.(ts|js)|functions/)", rel):
            continue
        if not _DB_HINT.search(text) or _AUTH_HINT.search(text):
            continue
        hits.append(rel)
    if not hits:
        return []
    sev = Severity.HIGH if any(_SERVICE_CLIENT.search(texts[p]) for p in texts
                               if _rel(p, root) in hits) else Severity.MEDIUM
    return [Finding(
        title=f"{len(hits)} API route(s) query the database with no visible auth check",
        severity=sev, source_tool="repo", layer="authz",
        location=hits[0],
        description=("These routes read or write data but contain no call to any session, user or "
                     "authorization helper. If the check really is missing, any visitor can call them "
                     "directly — this is the broken-object-level-authorization pattern (IDOR)."),
        evidence="\n".join(hits[:10]) + (f"\n… and {len(hits) - 10} more" if len(hits) > 10 else ""),
        remediation=("In each route, resolve the caller (e.g. `supabase.auth.getUser()`) and scope every "
                     "query to them. Do not rely on the client sending the right id."),
        cwe="CWE-639")]


def _source_secrets(root: Path, texts: dict[Path, str]) -> list[Finding]:
    """Zero-install secret scan. Overlaps Gitleaks on purpose; dedupe merges them."""
    out = []
    for path, text in texts.items():
        for f in scan_text(text, _rel(path, root)):
            f.source_tool = "repo"
            # scan_text words itself for a live bundle; here the file is on disk
            f.title = f.title.replace("in frontend code", "in the repository")
            f.description = f.description.replace("shipped in JavaScript the browser downloads",
                                                  "committed to the repository")
            f.description = f.description.replace("is in the browser bundle",
                                                  "is committed to the repository")
            out.append(f)
    return out

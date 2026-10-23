"""Ownership proof via the GitHub CLI.

DEVELOPMENT_PLAN §3: GitHub connect is the primary gate — it proves ownership
*and* unlocks the code layer in one step. We shell out to `gh`, which already
holds the user's credentials, so this tool never sees or stores a token.

ponytail: no persistence. A proof is cheap to re-establish (one API call), and a
cached "yes" on disk is a worse artifact than no cache at all.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

SLUG = re.compile(r"^(?:https://github\.com/|git@github\.com:)?([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
# Permissions that mean "this is yours". `pull` alone is not ownership.
OWNING = ("admin", "maintain", "push")


class NotVerified(Exception):
    pass


@dataclass
class Ownership:
    verified: bool
    method: str          # "github"
    subject: str         # "owner/repo"
    detail: str          # how we concluded it

    def __str__(self) -> str:
        return f"{self.subject} — {self.detail}" if self.verified else f"{self.subject} — NOT verified"


def is_slug(s: str) -> bool:
    """True for owner/repo or a github.com URL, false for a local path."""
    if Path(s).expanduser().exists():
        return False
    return bool(SLUG.match(s))


def parse_slug(s: str) -> str:
    m = SLUG.match(s)
    if not m:
        raise ValueError(f"not a GitHub repo: {s}")
    return f"{m.group(1)}/{m.group(2)}"


def available() -> bool:
    return shutil.which("gh") is not None


def _gh(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=timeout)


def verify(repo: str) -> Ownership:
    """Raise NotVerified unless `gh` says this account can write to the repo."""
    slug = parse_slug(repo)
    if not available():
        raise NotVerified("the GitHub CLI (`gh`) is not installed — see https://cli.github.com")

    auth = _gh("auth", "status")
    if auth.returncode != 0:
        raise NotVerified("not logged in to GitHub. Run: gh auth login")

    proc = _gh("api", f"repos/{slug}", "--jq", "{perms:.permissions, private:.private, name:.full_name}")
    if proc.returncode != 0:
        msg = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "unknown error"
        raise NotVerified(f"cannot read {slug} as the logged-in account: {msg}")

    data = json.loads(proc.stdout or "{}")
    perms = data.get("perms") or {}
    held = [p for p in OWNING if perms.get(p)]
    if not held:
        raise NotVerified(
            f"you have read-only access to {slug}. Repo scanning needs write access, "
            "because it is also how we confirm the app is yours.")

    return Ownership(True, "github", data.get("name") or slug,
                     f"write access confirmed via GitHub CLI ({', '.join(held)})")


def clone(repo: str, depth: int = 1) -> Path:
    """Shallow-clone a verified repo into a temp dir. Caller removes it (see §16: no retention)."""
    slug = parse_slug(repo)
    dest = Path(tempfile.mkdtemp(prefix="vaultrix-repo-"))
    proc = _gh("repo", "clone", slug, str(dest / "src"), "--", "--depth", str(depth), timeout=600)
    if proc.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise NotVerified(f"clone of {slug} failed: {proc.stderr.strip()[:300]}")
    return dest / "src"


if __name__ == "__main__":  # self-check — parsing only, no network
    assert parse_slug("owner/repo") == "owner/repo"
    assert parse_slug("https://github.com/owner/repo.git") == "owner/repo"
    assert parse_slug("git@github.com:owner/repo") == "owner/repo"
    assert is_slug("owner/repo") and not is_slug(".") and not is_slug("/tmp")
    assert not is_slug("not a repo at all")
    try:
        parse_slug("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("bare name must not parse as a repo")
    print("ownership self-check ok")

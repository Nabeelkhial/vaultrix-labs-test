"""Vaultrix Labs web front door (DEVELOPMENT_PLAN §3).

Login with GitHub, connect a repo you own, run the inspection, read the graded
report. Passive URL scans run inline; repo scans and sandbox attacks run as
background jobs (see jobs.py). The web layer holds no scanning logic — it calls
core/orchestrator, exactly like the CLI and MCP server (§13).

Auth:
  * Production — GitHub OAuth. Set VAULTRIX_GH_CLIENT_ID + VAULTRIX_GH_CLIENT_SECRET
    (register an OAuth App at github.com/settings/developers; callback
    <base>/auth/callback). The user's token is stored server-side in SQLite; the
    browser cookie carries only an opaque session id.
  * Dev — if those env vars are unset, a "Continue with local gh" button uses the
    machine's `gh auth token`. Clearly dev-only; never enabled when OAuth is set.
"""
from __future__ import annotations

import os
import subprocess
import secrets
import urllib.parse
from functools import wraps

import requests
from flask import (Flask, abort, redirect, render_template, request, session, url_for)

from core.orchestrator import attack_sandbox, scan_repo, scan_url, fix_findings
from interfaces.web import jobs

GH_CLIENT_ID = os.environ.get("VAULTRIX_GH_CLIENT_ID", "")
GH_CLIENT_SECRET = os.environ.get("VAULTRIX_GH_CLIENT_SECRET", "")
OAUTH_READY = bool(GH_CLIENT_ID and GH_CLIENT_SECRET)
# Docker + supabase-cli presence gates the attack/fix actions in the UI.
from scanners._tool import how as _tool_how
from scanners.trivy import TOOL as _TRIVY


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("VAULTRIX_SECRET_KEY") or secrets.token_hex(32)
    jobs.init()

    # --- auth helpers --------------------------------------------------------
    def current_user():
        return jobs.get_session(session.get("sid"))

    def login_required(fn):
        @wraps(fn)
        def wrap(*a, **k):
            if not current_user():
                return redirect(url_for("index"))
            return fn(*a, **k)
        return wrap

    @app.context_processor
    def inject():
        u = current_user()
        return {"user": u, "oauth_ready": OAUTH_READY,
                "docker_ready": bool(_tool_how(_TRIVY))}

    # --- pages ---------------------------------------------------------------
    @app.get("/")
    def index():
        if current_user():
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", jobs=jobs.list_jobs(current_user()["login"]))

    # --- GitHub OAuth --------------------------------------------------------
    @app.get("/login")
    def login():
        if not OAUTH_READY:
            abort(404)
        state = secrets.token_urlsafe(16)
        session["oauth_state"] = state
        params = urllib.parse.urlencode({
            "client_id": GH_CLIENT_ID, "scope": "repo read:user",
            "redirect_uri": url_for("callback", _external=True), "state": state})
        return redirect(f"https://github.com/login/oauth/authorize?{params}")

    @app.get("/auth/callback")
    def callback():
        if not OAUTH_READY:
            abort(404)
        if not request.args.get("state") or request.args.get("state") != session.pop("oauth_state", None):
            abort(400, "bad OAuth state")
        code = request.args.get("code")
        if not code:
            abort(400, "no code")
        tok = requests.post("https://github.com/login/oauth/access_token",
                            headers={"Accept": "application/json"},
                            data={"client_id": GH_CLIENT_ID, "client_secret": GH_CLIENT_SECRET,
                                  "code": code, "redirect_uri": url_for("callback", _external=True)},
                            timeout=20).json()
        token = tok.get("access_token")
        if not token:
            abort(400, f"token exchange failed: {tok.get('error_description', tok)}")
        login = requests.get("https://api.github.com/user",
                             headers={"Authorization": f"Bearer {token}"}, timeout=20).json().get("login")
        session["sid"] = jobs.new_session(login, token)
        return redirect(url_for("dashboard"))

    @app.post("/dev-login")
    def dev_login():
        """Dev-only: reuse the machine's gh token. Disabled when OAuth is configured."""
        if OAUTH_READY:
            abort(404)
        try:
            token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True,
                                   timeout=15).stdout.strip()
            login = subprocess.run(["gh", "api", "user", "--jq", ".login"], capture_output=True,
                                   text=True, timeout=15).stdout.strip()
        except Exception:
            token, login = "", ""
        if not token or not login:
            abort(400, "gh not authenticated on this host")
        session["sid"] = jobs.new_session(login, token)
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout():
        jobs.drop_session(session.pop("sid", None))
        return redirect(url_for("index"))

    # --- actions -------------------------------------------------------------
    @app.post("/scan-url")
    @login_required
    def scan_url_action():
        url = (request.form.get("url") or "").strip()
        if not url:
            return redirect(url_for("dashboard"))
        # passive, read-only, safe for any site -> run inline
        try:
            scan = scan_url(url)
        except Exception as e:
            return render_template("result.html", error=f"{type(e).__name__}: {e}", job=None)
        return render_template("result.html", result=jobs._scan_json_obj(scan), job=None)

    @app.get("/repos")
    @login_required
    def repos():
        u = current_user()
        r = requests.get("https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner",
                         headers={"Authorization": f"Bearer {u['token']}"}, timeout=30)
        repos = [{"full_name": x["full_name"], "private": x["private"],
                  "language": x.get("language"), "pushed_at": x.get("pushed_at", "")[:10]}
                 for x in (r.json() if r.status_code == 200 else [])]
        return render_template("repos.html", repos=repos)

    @app.post("/scan-repo")
    @login_required
    def scan_repo_action():
        u = current_user()
        repo = request.form.get("repo", "")
        jid = jobs.create_job(u["login"], "repo", repo,
                              lambda log: scan_repo(repo, log=log))
        return redirect(url_for("job_page", jid=jid))

    @app.post("/attack")
    @login_required
    def attack_action():
        u = current_user()
        repo, stack = request.form.get("repo", ""), request.form.get("stack", "supabase-next")
        if not bool(_tool_how(_TRIVY)):
            abort(400, "this host has no Docker worker; attack/fix need one")
        jid = jobs.create_job(u["login"], "attack", repo,
                              lambda log: attack_sandbox(repo, stack=stack, log=log))
        return redirect(url_for("job_page", jid=jid))

    @app.get("/job/<jid>")
    @login_required
    def job_page(jid):
        job = jobs.get_job(jid, owner=current_user()["login"])
        if not job:
            abort(404)
        return render_template("job.html", job=job)

    @app.get("/health")
    def health():
        return {"ok": True}

    return app


# jobs helper for the inline (non-job) path
def _scan_json_obj(scan):
    import json
    return json.loads(jobs._scan_json(scan))
jobs._scan_json_obj = _scan_json_obj  # type: ignore[attr-defined]


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)

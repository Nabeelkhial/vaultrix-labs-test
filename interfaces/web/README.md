# Vaultrix Labs — web front door

Login with GitHub, connect a repo you own, run the inspection, read the graded
report. The web layer holds no scanning logic — it calls `core/orchestrator`,
exactly like the CLI and MCP server (§13).

## Run locally

```bash
python3 -m venv .venv-web && .venv-web/bin/pip install -r interfaces/web/requirements.txt
PORT=5111 .venv-web/bin/python -m interfaces.web.app   # http://localhost:5111
```

Without OAuth configured, the landing page shows **Continue with local gh (dev)**,
which reuses this machine's `gh auth token`. That is for local development only and
is automatically disabled once OAuth is set.

## Real GitHub OAuth (for a deployed, multi-user app)

1. Register an OAuth App at <https://github.com/settings/developers> →
   **New OAuth App**.
   - Homepage URL: your deployment's base URL.
   - **Authorization callback URL**: `<base-url>/auth/callback`.
2. Set these environment variables (never commit them):

   ```
   VAULTRIX_GH_CLIENT_ID=<client id>
   VAULTRIX_GH_CLIENT_SECRET=<client secret>
   VAULTRIX_SECRET_KEY=<random 32+ byte hex, for signing session cookies>
   ```

The requested scope is `repo read:user` — `repo` is needed to list and clone the
private repositories a user asks us to scan. The user's token is stored
**server-side** in SQLite (`vaultrix_web.db`); the browser cookie carries only an
opaque session id.

## Deploy

```bash
docker build -f interfaces/web/Dockerfile -t vaultrix-web .
docker run -p 8000:8000 -e VAULTRIX_GH_CLIENT_ID=... -e VAULTRIX_GH_CLIENT_SECRET=... \
  -e VAULTRIX_SECRET_KEY=... vaultrix-web
```

### Host requirements by feature

| Feature | Needs |
|---|---|
| Passive URL scan | nothing extra |
| Repo scan (gitleaks/trivy/osv) | Docker available to the container (socket mount) or the native binaries |
| Sandbox **attack** / **fix** | Docker **and** the Supabase CLI on the worker |

Run attack/fix on a Docker-enabled worker; the UI hides those actions when Docker
is not detected. Jobs run in-process (one gunicorn worker) with a SQLite store —
swap in a real queue before scaling past one instance (see `jobs.py`).

## Privacy note

A repo scan clones your code to a temp dir and deletes it after the run (no
retention). OSV-Scanner sends the dependency **names and versions** to osv.dev to
look up CVEs — standard for SCA tools, but set it aside if you need a fully
offline scan (Trivy alone covers dependencies without that call).

"""Read-only HTTP + TLS helpers. Passive means: GET/HEAD only, no payloads, no auth attempts."""
from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlparse

UA = "VaultrixLabs/0.1 (passive security scan; +https://github.com/vaultrix-labs/vaultrix-labs-test)"
TIMEOUT = 10
MAX_BYTES = 2_000_000
WORKERS = 8  # ponytail: fixed pool, add rate limiting if a target complains


@dataclass
class Resp:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    # raw multi-value Set-Cookie lines, which dict(headers) would collapse
    cookies: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error == "" and self.status > 0


def fetch(url: str, method: str = "GET", origin: str | None = None) -> Resp:
    """Never raises. An HTTP error status is a result, not an exception."""
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if origin:
        hdrs["Origin"] = origin
    req = urllib.request.Request(url, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return _resp(r, r.read(MAX_BYTES))
    except urllib.error.HTTPError as e:              # 4xx/5xx still carry headers+body
        return _resp(e, e.read(MAX_BYTES), status=e.code)
    except Exception as e:                            # DNS, TLS, timeout, redirect loop
        return Resp(url=url, status=0, error=f"{type(e).__name__}: {e}")


def _resp(r, raw: bytes, status: int | None = None) -> Resp:
    h = r.headers
    return Resp(
        url=r.url if hasattr(r, "url") else r.geturl(),
        status=status if status is not None else r.status,
        headers={k.lower(): v for k, v in h.items()},
        body=raw.decode("utf-8", "replace"),
        cookies=h.get_all("Set-Cookie") or [],
    )


def fetch_many(urls: list[str]) -> list[Resp]:
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(fetch, urls))


def peer_cert(host: str, port: int = 443) -> tuple[dict | None, str | None, str]:
    """(cert, tls_version, error). Uses a verifying context, so an invalid cert IS the error."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(), tls.version(), ""
    except Exception as e:
        return None, None, f"{type(e).__name__}: {e}"


def normalize(url: str) -> str:
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if not p.netloc:
        raise ValueError(f"not a URL: {url}")
    return f"{p.scheme}://{p.netloc}{p.path.rstrip('/')}"


# --- authenticated client, for the proof layer (v0.3) ------------------------
import http.cookiejar  # noqa: E402
import json as _json  # noqa: E402


class Client:
    """A stateful HTTP client: one logged-in user. Holds a cookie jar and
    default headers (e.g. a bearer token), so the IDOR prober can act 'as user A'.

    Stdlib only — no requests. Read/write, since proving a finding may need a POST
    to log in, but it only ever touches the sandbox the tool built.
    """

    def __init__(self, base_url: str, headers: dict[str, str] | None = None):
        self.base = base_url.rstrip("/")
        self.headers = {"User-Agent": UA, **(headers or {})}
        self.jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method: str, path: str, *, json: dict | None = None,
                data: bytes | None = None, headers: dict | None = None) -> Resp:
        url = path if "://" in path else f"{self.base}/{path.lstrip('/')}"
        hdrs = {**self.headers, **(headers or {})}
        body = data
        if json is not None:
            body = _json.dumps(json).encode()
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, method=method, headers=hdrs, data=body)
        try:
            with self._opener.open(req, timeout=TIMEOUT) as r:
                return _resp(r, r.read(MAX_BYTES))
        except urllib.error.HTTPError as e:
            return _resp(e, e.read(MAX_BYTES), status=e.code)
        except Exception as e:
            return Resp(url=url, status=0, error=f"{type(e).__name__}: {e}")

    def get(self, path: str, **kw) -> Resp:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> Resp:
        return self.request("POST", path, **kw)

    def bearer(self, token: str) -> "Client":
        self.headers["Authorization"] = f"Bearer {token}"
        return self

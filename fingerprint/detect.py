"""Stack fingerprint from one root response. Drives which passive checks apply."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.net import Resp

# (label, where, pattern) — where is "body", "headers" or "cookies"
_SIGNS: list[tuple[str, str, str]] = [
    ("next.js",    "body",    r"/_next/static/|__NEXT_DATA__"),
    ("nuxt",       "body",    r"/_nuxt/|__NUXT__"),
    ("vite",       "body",    r"/assets/index-[\w]+\.js|/@vite/"),
    ("react",      "body",    r"react(-dom)?[-.@][\d.]+|data-reactroot"),
    ("svelte",     "body",    r"/_app/immutable/"),
    ("supabase",   "body",    r"[\w-]+\.supabase\.(co|in)|supabase-js"),
    ("firebase",   "body",    r"firebaseapp\.com|firebasejs"),
    ("wordpress",  "body",    r"/wp-content/|/wp-includes/"),
    ("laravel",    "cookies", r"XSRF-TOKEN|laravel_session"),
    ("php",        "cookies", r"PHPSESSID"),
    ("django",     "cookies", r"csrftoken|sessionid"),
    ("rails",      "cookies", r"_session_id|_rails_session"),
    ("php",        "headers", r"php"),
    ("vercel",     "headers", r"vercel"),
    ("netlify",    "headers", r"netlify"),
    ("cloudflare", "headers", r"cloudflare"),
]

_VERSION_HDRS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


@dataclass
class Stack:
    url: str
    tech: list[str] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)  # header -> value
    scripts: list[str] = field(default_factory=list)       # absolute JS bundle URLs

    @property
    def profile(self) -> str:
        """Coarse stack profile the orchestrator uses to pick checks."""
        if "supabase" in self.tech and "next.js" in self.tech:
            return "supabase-next"
        if "php" in self.tech or "laravel" in self.tech or "wordpress" in self.tech:
            return "php"
        if {"next.js", "nuxt", "vite", "react", "svelte"} & set(self.tech):
            return "spa"
        return "unknown"


def detect(root: Resp, bundles: list[Resp] = ()) -> Stack:
    """`bundles` are the already-fetched same-origin scripts. They matter: a Next.js
    app almost never names Supabase in its root HTML, only in the chunk it ships."""
    hay = {
        "body": "\n".join([root.body] + [b.body for b in bundles]),
        "headers": "\n".join(f"{k}: {v}" for k, v in root.headers.items()),
        "cookies": "\n".join(root.cookies),
    }
    tech = []
    for label, where, pat in _SIGNS:
        if label not in tech and re.search(pat, hay[where], re.I):
            tech.append(label)
    banners = {h: root.headers[h] for h in _VERSION_HDRS if h in root.headers}
    return Stack(url=root.url, tech=tech, banners=banners, scripts=script_urls(root))


def script_urls(root: Resp, limit: int = 25) -> list[str]:
    """Absolute URLs of same-origin <script src> bundles (where frontend secrets leak)."""
    from urllib.parse import urljoin, urlparse

    origin = urlparse(root.url).netloc
    out: list[str] = []
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', root.body, re.I):
        full = urljoin(root.url, src)
        if urlparse(full).netloc == origin and full not in out:
            out.append(full)
    return out[:limit]

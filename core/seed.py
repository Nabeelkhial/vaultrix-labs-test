"""The deterministic seed contract, shared by the sandbox and the proof layer.

The sandbox plants exactly this data; the prober reads the same object to know
who owns what and which string proves a leak. Two users is the minimum the IDOR
class needs: A must try to reach something only B owns.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SeedUser:
    email: str
    password: str
    # Resource paths this user legitimately owns, e.g. "/api/records/42".
    owns: list[str] = field(default_factory=list)
    # A string that appears in this user's data and nowhere else. If user A's
    # response ever contains user B's marker, A read B's data — that is the proof.
    marker: str = ""


@dataclass
class Seed:
    users: list[SeedUser]

    def other(self, user: SeedUser) -> SeedUser:
        return next(u for u in self.users if u is not user)

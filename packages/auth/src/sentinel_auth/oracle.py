"""SessionOracle (docs/01-architecture.md §6.5): the single most
underrated mechanism in the whole system.

Without this, a session that silently dies mid-scan produces 401/403
everywhere and the scan reports "excellent access control, no issues" —
docs/04-edge-cases.md §B1's catastrophic false negative. Establishing an
oracle means proving, by making both requests ourselves right now, that we
can actually tell an authenticated response from an anonymous one for this
app. Every access-control verdict later in the pipeline is only as
trustworthy as this check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sentinel_core.http_engine import AnonymousSession, EngineResponse, HttpEngine

from .persona_session import PersonaSession

OracleSignal = Literal["status_code", "body_contains"]


@dataclass(frozen=True, slots=True)
class SessionOracle:
    probe_method: str
    probe_url: str
    signal: OracleSignal
    authenticated_value: str

    async def check(self, engine: HttpEngine, persona: PersonaSession) -> bool:
        """True if `persona`'s current session still passes the oracle —
        i.e. still authenticated. Call this before trusting any
        authorization verdict about this persona (docs/02 Phase 6)."""
        response = await engine.request(self.probe_method, self.probe_url, persona=persona)
        return self._matches(response)

    def _matches(self, response: EngineResponse) -> bool:
        if self.signal == "status_code":
            return str(response.status_code) == self.authenticated_value
        return self.authenticated_value in response.text


@dataclass(frozen=True, slots=True)
class OracleEstablishmentResult:
    oracle: SessionOracle | None
    detail: str


async def establish_session_oracle(
    engine: HttpEngine,
    persona: PersonaSession,
    *,
    probe_url: str,
    probe_method: str = "GET",
) -> OracleEstablishmentResult:
    """Makes the same request as `persona` and as anonymous, and looks for a
    reliable differential. Returns ``oracle=None`` (docs/04 §B3) rather than
    guessing when no differential is found — callers must treat that target
    as one where authz confidence is capped, not silently proceed."""
    auth_response = await engine.request(probe_method, probe_url, persona=persona)
    anon_response = await engine.request(probe_method, probe_url, persona=AnonymousSession())

    if auth_response.status_code != anon_response.status_code:
        return OracleEstablishmentResult(
            oracle=SessionOracle(
                probe_method=probe_method,
                probe_url=probe_url,
                signal="status_code",
                authenticated_value=str(auth_response.status_code),
            ),
            detail=(
                f"Status code differs: authenticated={auth_response.status_code}, "
                f"anonymous={anon_response.status_code}."
            ),
        )

    if (
        auth_response.status_code == anon_response.status_code
        and auth_response.text != anon_response.text
    ):
        unique_line = _find_unique_line(auth_response.text, anon_response.text)
        if unique_line:
            return OracleEstablishmentResult(
                oracle=SessionOracle(
                    probe_method=probe_method,
                    probe_url=probe_url,
                    signal="body_contains",
                    authenticated_value=unique_line,
                ),
                detail="Same status code, but response body differs in an identifiable way.",
            )

    return OracleEstablishmentResult(
        oracle=None,
        detail=(
            f"No reliable differential found between authenticated and anonymous "
            f"responses at {probe_method} {probe_url} (both returned "
            f"{auth_response.status_code} with indistinguishable bodies). Access-control "
            "findings on this target are capped at 'probable' confidence — see "
            "docs/04-edge-cases.md §B3."
        ),
    )


def _find_unique_line(
    authenticated_text: str, anonymous_text: str, *, min_length: int = 6
) -> str | None:
    """A short, deterministic heuristic: the first line present in the
    authenticated body but not the anonymous one, long enough to not be
    coincidental whitespace. Good enough for the common case (an email,
    a username, a nav item that only renders when logged in); a
    genuinely fuzzy diff is more than this milestone needs."""
    anon_lines = set(anonymous_text.splitlines())
    for line in authenticated_text.splitlines():
        stripped = line.strip()
        if len(stripped) >= min_length and stripped not in anon_lines:
            return stripped
    return None

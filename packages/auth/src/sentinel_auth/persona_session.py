"""PersonaSession: the bridge between a replayed login (Playwright
storage_state) and sentinel_core.http_engine's SessionState protocol
(cookies() + extra_headers()) — this is what lets HttpEngine attach a
persona's identity to a plain HTTP request without knowing anything about
Playwright or how the session was established.
"""

from __future__ import annotations

from sentinel_core.session_import import SESSION_HEADERS_KEY


class PersonaSession:
    def __init__(
        self, persona_id: str, storage_state: dict, *, target_host: str | None = None
    ) -> None:
        self.persona_id = persona_id
        self._storage_state = storage_state
        self._target_host = target_host

    def cookies(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for cookie in self._storage_state.get("cookies", []):
            domain = cookie.get("domain", "").lstrip(".")
            if self._target_host and domain and not self._domain_matches(domain):
                continue  # a cookie scoped to a different domain (e.g. a
                # third-party IdP visited mid-login) never belongs on a
                # request to our actual target — see docs/06 scope discipline.
            result[cookie["name"]] = cookie["value"]
        return result

    def extra_headers(self) -> dict[str, str]:
        # A header login (v1 #1) carries its pasted header in the session
        # state (sentinel_core.session_import). HttpEngine only sends
        # requests the ScopeGuard allows, i.e. to the target's own hosts.
        # Tokens an app keeps in localStorage are still not picked up
        # automatically — use a header login for those.
        return dict(self._storage_state.get(SESSION_HEADERS_KEY) or {})

    def _domain_matches(self, cookie_domain: str) -> bool:
        host = self._target_host or ""
        return host == cookie_domain or host.endswith(f".{cookie_domain}")

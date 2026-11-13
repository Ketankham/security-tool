"""Which stored cookies a persona's HTTP requests carry (QA #37)."""

from __future__ import annotations

from sentinel_auth import PersonaSession


def _state(*domains: str) -> dict:
    return {"cookies": [{"name": f"c{i}", "value": d, "domain": d} for i, d in enumerate(domains)]}


def test_cookies_for_the_targets_subdomains_are_kept():
    """Target "abhyaasika.com", app on www.: the session cookie is set for
    www.abhyaasika.com and must be sent, or every replay is logged out."""
    session = PersonaSession(
        "p",
        _state("www.abhyaasika.com", ".abhyaasika.com", "abhyaasika.com"),
        target_host="abhyaasika.com",
    )
    assert set(session.cookies().values()) == {
        "www.abhyaasika.com",
        ".abhyaasika.com",
        "abhyaasika.com",
    }


def test_parent_domain_cookies_are_kept_and_other_sites_dropped():
    session = PersonaSession(
        "p",
        _state(".abhyaasika.com", "login.microsoftonline.com", "evil-abhyaasika.com"),
        target_host="www.abhyaasika.com",
    )
    assert list(session.cookies().values()) == [".abhyaasika.com"]

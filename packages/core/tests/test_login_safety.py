"""QA #23: where a login recipe may send the browser (and the password)."""

from __future__ import annotations

import pytest
from sentinel_core.login_safety import host_is_on_target, login_navigation_problems


def _recipe(start_url: str, *gotos: str, allow_off_domain: bool = False) -> dict:
    steps = [{"action": "goto", "value": g} for g in gotos]
    steps.append({"action": "fill_secret", "selector": "#p", "credential_ref": "password"})
    return {"start_url": start_url, "steps": steps, "allow_off_domain": allow_off_domain}


@pytest.mark.parametrize(
    "url",
    [
        "https://client.test/login",
        "http://client.test:8080/login",
        "https://app.client.test/sign-in",
        "HTTPS://CLIENT.TEST/login",
    ],
)
def test_on_target_http_urls_are_fine(url):
    assert login_navigation_problems(_recipe(url), "client.test") == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("javascript:alert(1)", "must start with http"),
        ("data:text/html,<form>", "must start with http"),
        ("file:///etc/passwd", "must start with http"),
        ("//client.test/login", "must start with http"),
        ("https:///login", "no host"),
        ("https://evil.example.org/login", "not on client.test"),
        ("https://client.test.evil.org/login", "not on client.test"),
        ("https://notclient.test/login", "not on client.test"),
    ],
)
def test_unsafe_login_urls_are_reported(url, expected):
    problems = login_navigation_problems(_recipe(url), "client.test")
    assert problems and expected in problems[0]


def test_goto_steps_are_checked_too():
    problems = login_navigation_problems(
        _recipe("https://client.test/login", "https://evil.example.org/step2"), "client.test"
    )
    assert len(problems) == 1 and "step 1 (goto)" in problems[0]


def test_off_domain_needs_explicit_confirmation_but_scheme_never_relaxes():
    sso = "https://login.microsoftonline.com/x"
    assert login_navigation_problems(_recipe(sso, allow_off_domain=True), "client.test") == []
    js = _recipe("javascript:alert(1)", allow_off_domain=True)
    assert login_navigation_problems(js, "client.test")


def test_legacy_unnormalised_target_root_is_tolerated():
    # Targets saved before root domains were normalised (e.g. "https://example.com").
    assert host_is_on_target("app.example.com", "https://Example.com/")

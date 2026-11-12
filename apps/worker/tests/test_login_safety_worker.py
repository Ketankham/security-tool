"""QA #23 at replay time: a recipe saved before the API checked login URLs
must never get the password typed into it."""

from __future__ import annotations

from types import SimpleNamespace

from sentinel_worker_app.auth_adapter import establish_persona


class _ExplodingCrypto:
    def decrypt(self, *a, **k):  # pragma: no cover - must never be reached
        raise AssertionError("password was decrypted for an unsafe recipe")


async def test_unsafe_stored_recipe_is_blocked_before_the_password_is_decrypted():
    persona = SimpleNamespace(
        login_recipe={
            "start_url": "javascript:alert(1)",
            "steps": [{"action": "fill_secret", "selector": "#p", "credential_ref": "pw"}],
            "success_assertion": {"kind": "url_contains", "value": "/x"},
        },
        credential=SimpleNamespace(ciphertext=b"x"),
    )
    result = await establish_persona(
        persona=persona,
        browser=None,
        crypto=_ExplodingCrypto(),
        org_data_key=b"k",
        engine=None,
        oracle_probe_url="https://client.test/",
        target_root_domain="client.test",
    )
    assert result.available is False
    assert result.unavailable_reason.startswith("Login blocked:")
    assert "must start with http" in result.unavailable_reason


async def test_off_target_stored_recipe_is_blocked():
    persona = SimpleNamespace(
        login_recipe={
            "start_url": "https://evil.example.org/login",
            "steps": [{"action": "fill_secret", "selector": "#p", "credential_ref": "pw"}],
            "success_assertion": {"kind": "url_contains", "value": "/x"},
        },
        credential=SimpleNamespace(ciphertext=b"x"),
    )
    result = await establish_persona(
        persona=persona,
        browser=None,
        crypto=_ExplodingCrypto(),
        org_data_key=b"k",
        engine=None,
        oracle_probe_url="https://client.test/",
        target_root_domain="client.test",
    )
    assert not result.available and "not on client.test" in result.unavailable_reason

"""LoginReplayer against a real server + real (headless) browser — no
mocking. If this passes, the recipe format genuinely drives a login."""

from __future__ import annotations

from sentinel_auth.models import Credential, LoginRecipe, LoginStep, SuccessAssertion
from sentinel_auth.replay import LoginReplayer


def _recipe(login_server: str) -> LoginRecipe:
    return LoginRecipe(
        start_url=f"{login_server}/login",
        steps=(
            LoginStep(action="fill", selector="input[name=username]", value="alice"),
            LoginStep(action="fill_secret", selector="input[name=password]", credential_ref="pw"),
            LoginStep(action="click", selector="button[type=submit]"),
        ),
        success_assertion=SuccessAssertion(kind="url_contains", value="/dashboard"),
    )


async def test_successful_login_returns_storage_state(login_server, browser):
    replayer = LoginReplayer(browser)
    recipe = _recipe(login_server)
    credentials = {"pw": Credential(ref="pw", secret="correct-horse-battery-staple")}

    result = await replayer.replay(recipe, credentials=credentials)

    assert result.success
    assert result.storage_state is not None
    cookie_names = {c["name"] for c in result.storage_state["cookies"]}
    assert "session" in cookie_names


async def test_wrong_password_fails_the_success_assertion(login_server, browser):
    replayer = LoginReplayer(browser)
    recipe = _recipe(login_server)
    credentials = {"pw": Credential(ref="pw", secret="totally-wrong")}

    result = await replayer.replay(recipe, credentials=credentials)

    assert not result.success
    assert result.storage_state is None
    assert "Success assertion failed" in result.error


async def test_missing_credential_against_real_server_fails_with_keyerror_message(
    login_server, browser
):
    replayer = LoginReplayer(browser)
    recipe = _recipe(login_server)

    result = await replayer.replay(recipe, credentials={})  # no "pw" ref provided

    assert not result.success
    assert "missing credential" in result.error

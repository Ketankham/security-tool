from sentinel_core.redact import REDACTED, redact_text, redact_url


def test_sensitive_query_values_and_url_credentials_are_blanked():
    out = redact_url("https://user:pw@app.test/cb?code=abc123&page=2&access_token=xyz&x=")
    assert "pw" not in out and "abc123" not in out and "xyz" not in out
    assert "page=2" in out and "app.test/cb" in out


def test_non_sensitive_urls_are_untouched():
    assert redact_url("https://app.test/dashboard?tab=a&page=2") == (
        "https://app.test/dashboard?tab=a&page=2"
    )


def test_text_redaction_covers_secrets_bearers_jwts_and_cookies():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
    text = (
        "login ok, cookie: session=SESSIONVALUE123; theme=dark. "
        "Authorization: Bearer abcdefgh12345. "
        f"jwt {jwt} secret=HUNTER2HUNTER2 at https://x.test/a?token=tok_live_999"
    )
    out = redact_text(text, secrets=["HUNTER2HUNTER2"])
    for leaked in ("SESSIONVALUE123", "abcdefgh12345", jwt, "HUNTER2HUNTER2", "tok_live_999"):
        assert leaked not in out
    assert REDACTED in out


def test_short_secrets_are_not_used_for_replacement():
    # A 3-character "secret" would mangle ordinary words.
    assert redact_text("the cat sat", secrets=["cat"]) == "the cat sat"

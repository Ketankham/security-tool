from sentinel_core import authorisation


def test_the_statement_names_the_client_and_the_target():
    text = authorisation.render("Acme Ltd", "shop.acme.test")
    assert text == (
        "I confirm Acme Ltd has authorised in writing active testing (port scanning, "
        "directory brute forcing) of shop.acme.test for this scan."
    )


def test_all_ports_has_its_own_statement():
    text = authorisation.render_all_ports("shop.acme.test")
    assert (
        text
        == "I confirm the authorisation covers scanning all 65,535 TCP ports of shop.acme.test."
    )


def test_templates_expose_the_placeholders_the_dashboard_fills_in():
    assert "{client}" in authorisation.STATEMENT_TEMPLATE
    assert "{target}" in authorisation.STATEMENT_TEMPLATE
    assert "{target}" in authorisation.ALL_PORTS_STATEMENT
    assert authorisation.STATEMENT_VERSION == "1"

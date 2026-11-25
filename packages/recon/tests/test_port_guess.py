"""Port-number service guesses: the table and the lookup."""

import pytest
from sentinel_recon import port_guess


@pytest.mark.parametrize(
    ("port", "name"),
    [
        (21, "ftp"),
        (22, "ssh"),
        (25, "smtp"),
        (53, "domain"),
        (80, "http"),
        (110, "pop3"),
        (143, "imap"),
        (443, "https"),
        (445, "microsoft-ds"),
        (465, "smtps"),
        (587, "submission"),
        (993, "imaps"),
        (995, "pop3s"),
        (1433, "ms-sql"),
        (1521, "oracle"),
        (2049, "nfs"),
        (2375, "docker"),
        (3000, "http"),
        (3306, "mysql"),
        (3389, "ms-wbt-server"),
        (5432, "postgresql"),
        (5900, "vnc"),
        (6379, "redis"),
        (8080, "http-proxy"),
        (8443, "https-alt"),
        (9200, "elasticsearch"),
        (11211, "memcached"),
        (27017, "mongodb"),
    ],
)
def test_common_ports_are_guessed(port, name):
    assert port_guess.guess(port) == name


@pytest.mark.parametrize("port", [0, 1, 12345, 47123, 65535, -1, 70000])
def test_unknown_ports_give_none(port):
    assert port_guess.guess(port) is None
    assert port_guess.guess_note(port) is None


def test_the_table_is_about_forty_well_formed_entries():
    assert 35 <= len(port_guess.COMMON_PORTS) <= 60
    for port, (service, note) in port_guess.COMMON_PORTS.items():
        assert 1 <= port <= 65535
        assert service and service == service.lower() and " " not in service
        assert note
        assert port_guess.guess(port) == service
        assert port_guess.guess_note(port) == note


def test_names_fit_the_port_services_columns():
    assert all(len(s) <= 100 for s, _ in port_guess.COMMON_PORTS.values())


def test_unencrypted_docker_is_called_out():
    assert "unencrypted" in (port_guess.guess_note(2375) or "")


def test_confidence_label_is_the_one_the_database_stores():
    assert port_guess.CONFIDENCE == "port_guess"

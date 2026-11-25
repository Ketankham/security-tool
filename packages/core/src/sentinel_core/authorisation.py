"""The "I'm authorised" statement a person confirms before a scan may use an
active tool (directory brute force, port scanning).

The wording lives here, in one place, so the API stores exactly what the
person was shown and the dashboard renders the same text. Changing the
wording means bumping STATEMENT_VERSION: a client that still holds the old
version is refused (409) and has to reload and confirm again, so a stored
record always matches a statement that was really on screen.
"""

from __future__ import annotations

STATEMENT_VERSION = "1"

STATEMENT_TEMPLATE = (
    "I confirm {client} has authorised in writing active testing (port scanning, "
    "directory brute forcing) of {target} for this scan."
)

ALL_PORTS_STATEMENT = (
    "I confirm the authorisation covers scanning all 65,535 TCP ports of {target}."
)

MAX_CLIENT_NAME_CHARS = 200


def render(client: str, target: str) -> str:
    """The confirmation sentence for this client and target."""
    return STATEMENT_TEMPLATE.format(client=client, target=target)


def render_all_ports(target: str) -> str:
    return ALL_PORTS_STATEMENT.format(target=target)

"""Active tools at the API: validation, the authorisation record, retry, cancel.

Only directory brute force is implemented in this build
(IMPLEMENTED_ACTIVE_TOOLS); port scanning and all-ports are still refused as
"not available yet". The tests that exercise the port rules switch all three on
for the duration of the test; the first tests show what a real caller sees today.
"""

from __future__ import annotations

import uuid

import pytest
from redis import asyncio as aioredis
from sentinel_core import authorisation as auth_text
from sentinel_core.state_machine import ScanState
from sentinel_db.models import Scan, ScanAuthorisation
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

pytestmark = pytest.mark.integration

SECRET = "s3cret-for-tests"
REDIS_URL = "redis://localhost:6379/0"


def who(name: str = "alice", **extra: str) -> dict[str, str]:
    return {"X-Sentinel-Proxy-Secret": SECRET, "X-Sentinel-User": name, **extra}


def confirm(**overrides) -> dict:
    body = {
        "accepted": True,
        "client_name": "Acme Ltd",
        "statement_version": auth_text.STATEMENT_VERSION,
        "all_ports_confirmed": False,
    }
    body.update(overrides)
    return body


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for name in ("REQUIRE_IDENTITY", "DEV_IDENTITY", "ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REQUIRE_OWNERSHIP_VERIFICATION", "false")
    monkeypatch.setenv("SENTINEL_PROXY_SECRET", SECRET)
    monkeypatch.setenv("REDIS_URL", REDIS_URL)


@pytest.fixture
def all_tools(monkeypatch):
    monkeypatch.setattr(
        "sentinel_core.scan_options.IMPLEMENTED_ACTIVE_TOOLS",
        ("dir_bruteforce", "port_scan", "all_ports"),
    )


@pytest.fixture
async def redis_db():
    client = aioredis.from_url(REDIS_URL)
    try:
        await client.ping()
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"Redis not reachable at {REDIS_URL}: {exc}")
    yield client
    for key in await client.keys("sentinel:scan-cancel:*"):
        await client.delete(key)
    await client.aclose()


async def make_target(client, slug: str, **target_fields):
    org = (await client.post("/organizations", json={"name": slug, "slug": slug})).json()
    headers = {"X-Org-Id": org["id"]}
    target = (
        await client.post(
            "/targets",
            json={"root_domain": f"{slug}.test", "display_name": f"{slug} app", **target_fields},
            headers=headers,
        )
    ).json()
    return headers, target


async def start(client, target, headers, **body):
    return await client.post(f"/targets/{target['id']}/scans", json=body, headers=headers)


async def set_state(db_engine, scan_id, state):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        row = await session.get(Scan, uuid.UUID(scan_id))
        row.state = state
        await session.commit()


async def count(db_engine, model) -> int:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        return (await session.execute(select(func.count()).select_from(model))).scalar_one()


# --- Today's behaviour: only directory brute force is available ----------------


@pytest.mark.parametrize(
    ("flag", "label"),
    [
        ("port_scan", "Port scanning"),
        ("all_ports", "All 65,535 ports"),
    ],
)
async def test_any_real_tool_request_is_refused_as_not_available_yet(
    client, no_dispatch, flag, label
):
    headers, target = await make_target(client, f"na-{flag.replace('_', '-')}")
    resp = await start(
        client,
        target,
        {**headers, **who()},
        **{flag: True, "recon_profile": "full", "authorisation": confirm(all_ports_confirmed=True)},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == f"{label} is not available yet."


async def test_not_available_is_reported_before_the_missing_identity(client, no_dispatch):
    headers, target = await make_target(client, "na-before-identity")
    resp = await start(client, target, headers, port_scan=True)  # no identity, no confirmation
    assert resp.status_code == 422
    assert resp.json()["detail"] == "Port scanning is not available yet."


async def test_directory_brute_force_is_accepted_with_an_identity_and_the_confirmation(
    client, db_engine, no_dispatch
):
    headers, target = await make_target(client, "dir-accepted")
    resp = await start(
        client, target, {**headers, **who()}, dir_bruteforce=True, authorisation=confirm()
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["requested_by"] == "alice"
    assert scan["options"]["dir_bruteforce"] is True
    assert scan["options"]["wordlist"] == "sentinel-core"
    auth = (await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)).json()
    assert auth["tools"] == ["dir_bruteforce"]
    assert auth["username"] == "alice"
    assert await count(db_engine, ScanAuthorisation) == 1


async def test_directory_brute_force_still_needs_the_identity_and_the_confirmation(
    client, db_engine, no_dispatch
):
    headers, target = await make_target(client, "dir-needs-both")
    no_identity = await start(client, target, headers, dir_bruteforce=True, authorisation=confirm())
    assert no_identity.status_code == 403
    no_confirmation = await start(client, target, {**headers, **who()}, dir_bruteforce=True)
    assert no_confirmation.status_code == 422
    assert await count(db_engine, Scan) == 0


async def test_the_seclists_wordlist_is_accepted_for_directory_brute_force_on_full(
    client, no_dispatch
):
    headers, target = await make_target(client, "dir-seclists-ok")
    resp = await start(
        client,
        target,
        {**headers, **who()},
        dir_bruteforce=True,
        recon_profile="full",
        wordlist="seclists-common",
        authorisation=confirm(),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["options"]["wordlist"] == "seclists-common"


@pytest.mark.parametrize(
    "body",
    [
        {"wordlist": "seclists-common", "dir_bruteforce": True, "recon_profile": "light"},
        {"wordlist": "seclists-common", "recon_profile": "full"},
        {"wordlist": "seclists-common"},
    ],
)
async def test_the_seclists_rules_hold_with_only_the_real_implemented_tools(
    client, no_dispatch, body
):
    headers, target = await make_target(client, f"dir-seclists-{uuid.uuid4().hex[:6]}")
    resp = await start(client, target, {**headers, **who()}, authorisation=confirm(), **body)
    assert resp.status_code == 422
    assert resp.json()["detail"] == (
        "The SecLists wordlist is only available for directory brute forcing on the Full recon "
        "profile."
    )


async def test_a_passive_scan_stores_every_option_and_needs_no_identity(client, no_dispatch):
    headers, target = await make_target(client, "passive-ok")
    resp = await start(client, target, headers)
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["requested_by"] is None
    assert scan["options"] == {
        "speed": "normal",
        "depth": "standard",
        "recon_profile": "light",
        "dir_bruteforce": False,
        "port_scan": False,
        "all_ports": False,
        "wordlist": "sentinel-core",
        "target_environment": "production",
    }
    auth = await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)
    assert auth.status_code == 404
    assert auth.json()["detail"] == "No authorisation record: this scan used no active tools."


async def test_a_passive_scan_records_who_started_it(client, no_dispatch):
    headers, target = await make_target(client, "passive-who")
    resp = await start(client, target, {**headers, **who("bob")})
    assert resp.json()["requested_by"] == "bob"


async def test_a_passive_scan_ignores_a_spoofed_user_header(client, no_dispatch):
    headers, target = await make_target(client, "passive-spoof")
    resp = await start(client, target, {**headers, "X-Sentinel-User": "evil"})
    assert resp.json()["requested_by"] is None


async def test_an_authorisation_sent_with_no_tools_is_ignored_and_not_stored(
    client, db_engine, no_dispatch
):
    headers, target = await make_target(client, "auth-no-tools")
    resp = await start(client, target, {**headers, **who()}, authorisation=confirm())
    assert resp.status_code == 201
    assert resp.json()["requested_by"] == "alice"
    assert await count(db_engine, ScanAuthorisation) == 0


async def test_target_environment_defaults_from_the_target(client, no_dispatch):
    headers, prod = await make_target(client, "env-prod")
    assert (await start(client, prod, headers)).json()["options"]["target_environment"] == (
        "production"
    )
    headers, stage = await make_target(client, "env-stage", is_production=False)
    resp = await start(client, stage, headers)
    assert resp.json()["options"]["target_environment"] == "staging"
    over = await start(client, stage, headers, target_environment="production")
    assert over.json()["options"]["target_environment"] == "production"
    bad = await start(client, stage, headers, target_environment="moon")
    assert bad.status_code == 422


# --- Every validation row ------------------------------------------------------


async def test_all_ports_needs_port_scanning(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-ports-needs-scan")
    resp = await start(
        client,
        target,
        {**headers, **who()},
        all_ports=True,
        recon_profile="full",
        authorisation=confirm(all_ports_confirmed=True),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "All 65,535 ports needs port scanning switched on."


async def test_all_ports_is_full_profile_only(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-ports-full")
    resp = await start(
        client,
        target,
        {**headers, **who()},
        port_scan=True,
        all_ports=True,
        recon_profile="light",
        authorisation=confirm(all_ports_confirmed=True),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "All 65,535 ports is only available on the Full recon profile."


@pytest.mark.parametrize(
    "body",
    [
        {"wordlist": "seclists-common", "dir_bruteforce": True, "recon_profile": "light"},
        {"wordlist": "seclists-common", "port_scan": True, "recon_profile": "full"},
        {"wordlist": "seclists-common", "recon_profile": "full"},
        {"wordlist": "seclists-common"},
    ],
)
async def test_seclists_needs_full_profile_and_directory_brute_force(
    client, no_dispatch, all_tools, body
):
    headers, target = await make_target(client, f"v-seclists-{uuid.uuid4().hex[:6]}")
    resp = await start(client, target, {**headers, **who()}, authorisation=confirm(), **body)
    assert resp.status_code == 422
    assert resp.json()["detail"] == (
        "The SecLists wordlist is only available for directory brute forcing on the Full recon "
        "profile."
    )


async def test_active_tools_need_a_verified_identity(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-identity")
    for extra in (
        {},
        {"X-Sentinel-User": "alice"},
        {"X-Sentinel-User": "alice", "X-Sentinel-Proxy-Secret": "no"},
    ):
        resp = await start(
            client, target, {**headers, **extra}, dir_bruteforce=True, authorisation=confirm()
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == (
            "Active tools need a signed-in user, and this request has no verified identity. "
            "Open Sentinel through its sign-in page."
        )


async def test_identity_is_checked_before_the_confirmation(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-identity-first")
    resp = await start(client, target, headers, dir_bruteforce=True)
    assert resp.status_code == 403


@pytest.mark.parametrize(
    "authorisation",
    [
        None,
        confirm(accepted=False),
        confirm(client_name=""),
        confirm(client_name="   "),
    ],
)
async def test_active_tools_need_the_confirmation(client, no_dispatch, all_tools, authorisation):
    headers, target = await make_target(client, f"v-confirm-{uuid.uuid4().hex[:6]}")
    resp = await start(
        client, target, {**headers, **who()}, dir_bruteforce=True, authorisation=authorisation
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == (
        "Active tools need the 'I'm authorised' confirmation: name the client and tick the box."
    )


async def test_a_stale_statement_version_is_a_409(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-version")
    resp = await start(
        client,
        target,
        {**headers, **who()},
        dir_bruteforce=True,
        authorisation=confirm(statement_version="0"),
    )
    assert resp.status_code == 409
    assert resp.json()["detail"] == (
        f"The authorisation statement has changed (now version {auth_text.STATEMENT_VERSION}). "
        "Reload the page and confirm again."
    )


async def test_all_ports_needs_its_own_confirmation(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-allports-confirm")
    resp = await start(
        client,
        target,
        {**headers, **who()},
        port_scan=True,
        all_ports=True,
        recon_profile="full",
        authorisation=confirm(all_ports_confirmed=False),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "Scanning all 65,535 ports needs its own confirmation."


async def test_a_refused_request_creates_nothing(client, db_engine, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-nothing-created")
    for body in (
        {"dir_bruteforce": True},
        {"dir_bruteforce": True, "authorisation": confirm(statement_version="0")},
        {"all_ports": True},
    ):
        resp = await start(client, target, {**headers, **who()}, **body)
        assert resp.status_code >= 400
    assert await count(db_engine, Scan) == 0
    assert await count(db_engine, ScanAuthorisation) == 0


async def test_the_pydantic_layer_rejects_unknown_values(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "v-pydantic")
    assert (await start(client, target, headers, wordlist="everything")).status_code == 422
    assert (await start(client, target, headers, dir_bruteforce="maybe")).status_code == 422
    too_long = confirm(client_name="x" * 201)
    resp = await start(
        client, target, {**headers, **who()}, dir_bruteforce=True, authorisation=too_long
    )
    assert resp.status_code == 422


# --- Creating an active scan: the record, atomically ---------------------------


async def test_creating_an_active_scan_stores_the_authorisation_with_it(
    client, db_engine, no_dispatch, all_tools
):
    headers, target = await make_target(client, "c-ok")
    resp = await start(
        client,
        target,
        {**headers, **who("alice", **{"X-Forwarded-For": "198.51.100.4", "User-Agent": "UA/9"})},
        dir_bruteforce=True,
        port_scan=True,
        all_ports=True,
        recon_profile="full",
        speed="gentle",
        authorisation=confirm(client_name="  Acme Ltd  ", all_ports_confirmed=True),
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    assert scan["requested_by"] == "alice"
    assert scan["state"] == "queued"
    assert scan["options"]["dir_bruteforce"] is True
    assert scan["options"]["all_ports"] is True

    got = await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)
    assert got.status_code == 200, got.text
    rec = got.json()
    assert rec["scan_id"] == scan["id"]
    assert rec["target_id"] == target["id"]
    assert rec["username"] == "alice"
    assert rec["client_name"] == "Acme Ltd"  # stripped
    assert rec["target_name"] == "c-ok.test"
    assert rec["tools"] == ["dir_bruteforce", "port_scan", "all_ports"]
    assert rec["all_ports_confirmed"] is True
    assert rec["target_environment"] == "production"
    assert rec["statement_version"] == auth_text.STATEMENT_VERSION
    assert rec["statement_text"].startswith(auth_text.render("Acme Ltd", "c-ok.test"))
    assert auth_text.render_all_ports("c-ok.test") in rec["statement_text"]
    assert rec["options_snapshot"]["speed"] == "gentle"
    assert rec["options_snapshot"]["recon_profile"] == "full"
    assert rec["client_ip"] == "198.51.100.4"
    assert rec["user_agent"] == "UA/9"
    assert rec["carried_over_from_scan_id"] is None
    assert rec["accepted_at"]


async def test_the_statement_of_a_directory_only_scan_has_no_all_ports_sentence(
    client, no_dispatch, all_tools
):
    headers, target = await make_target(client, "c-dir-only")
    scan = (
        await start(
            client, target, {**headers, **who()}, dir_bruteforce=True, authorisation=confirm()
        )
    ).json()
    rec = (await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)).json()
    assert rec["tools"] == ["dir_bruteforce"]
    assert rec["all_ports_confirmed"] is False
    assert "65,535" not in rec["statement_text"]


async def test_a_staging_target_is_recorded_as_staging(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "c-staging", is_production=False)
    scan = (
        await start(client, target, {**headers, **who()}, port_scan=True, authorisation=confirm())
    ).json()
    rec = (await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)).json()
    assert rec["target_environment"] == "staging"


async def test_a_dispatch_failure_still_leaves_the_authorisation_record(
    client, db_engine, monkeypatch, all_tools
):
    monkeypatch.setattr("sentinel_api_app.routers.scans.dispatch_scan", lambda scan_id: False)
    headers, target = await make_target(client, "c-dispatch-fails")
    resp = await start(
        client, target, {**headers, **who()}, dir_bruteforce=True, authorisation=confirm()
    )
    assert resp.status_code == 201
    scan = resp.json()
    assert scan["state"] == "failed"
    assert "job queue" in scan["fail_reason"]
    rec = await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)
    assert rec.status_code == 200
    assert rec.json()["username"] == "alice"


async def test_scan_and_authorisation_are_created_together_or_not_at_all(
    client, db_engine, no_dispatch, all_tools, monkeypatch
):
    def explode(**_kwargs):
        raise ValueError("could not build the record")

    monkeypatch.setattr("sentinel_api_app.routers.scans._authorisation_row", explode)
    headers, target = await make_target(client, "c-atomic")
    with pytest.raises(ValueError):
        await start(
            client, target, {**headers, **who()}, dir_bruteforce=True, authorisation=confirm()
        )
    # the scan that was flushed in the same transaction is gone with it
    assert await count(db_engine, Scan) == 0
    assert await count(db_engine, ScanAuthorisation) == 0


async def test_the_authorisation_of_another_orgs_scan_is_a_404(client, no_dispatch, all_tools):
    headers, target = await make_target(client, "c-org-a")
    other_headers, _ = await make_target(client, "c-org-b")
    scan = (
        await start(
            client, target, {**headers, **who()}, dir_bruteforce=True, authorisation=confirm()
        )
    ).json()
    resp = await client.get(f"/scans/{scan['id']}/authorisation", headers=other_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Scan not found."


# --- Retry ---------------------------------------------------------------------


async def active_scan(client, db_engine, target, headers, state=ScanState.FAILED, **body):
    resp = await start(
        client,
        target,
        {**headers, **who()},
        dir_bruteforce=True,
        authorisation=confirm(),
        **body,
    )
    assert resp.status_code == 201, resp.text
    scan = resp.json()
    await set_state(db_engine, scan["id"], state)
    return scan


async def test_retrying_a_passive_scan_needs_no_body_and_works_as_before(
    client, db_engine, no_dispatch
):
    headers, target = await make_target(client, "r-passive")
    scan = (await start(client, target, headers, speed="gentle")).json()
    await set_state(db_engine, scan["id"], ScanState.FAILED)
    resp = await client.post(f"/scans/{scan['id']}/retry", headers=headers)
    assert resp.status_code == 201
    new = resp.json()
    assert new["triggered_by"] == "retry"
    assert new["options"]["speed"] == "gentle"
    assert new["requested_by"] is None


async def test_retrying_a_passive_scan_ignores_active_tool_fields_in_the_body(
    client, db_engine, no_dispatch
):
    headers, target = await make_target(client, "r-passive-body")
    scan = (await start(client, target, headers)).json()
    await set_state(db_engine, scan["id"], ScanState.FAILED)
    resp = await client.post(
        f"/scans/{scan['id']}/retry",
        json={"drop_active_tools": True, "authorisation": confirm()},
        headers={**headers, **who("carol")},
    )
    assert resp.status_code == 201
    assert resp.json()["requested_by"] == "carol"
    # nothing active was used, so nothing is stored
    assert (
        await client.get(f"/scans/{resp.json()['id']}/authorisation", headers=headers)
    ).status_code == 404


async def test_retrying_an_active_scan_without_a_body_is_a_409(
    client, db_engine, no_dispatch, all_tools
):
    headers, target = await make_target(client, "r-409")
    scan = await active_scan(client, db_engine, target, headers, port_scan=True)
    resp = await client.post(f"/scans/{scan['id']}/retry", headers={**headers, **who()})
    assert resp.status_code == 409
    assert resp.json()["detail"] == (
        "This scan used active tools (Directory brute force, Port scanning). Retrying needs the "
        "'I'm authorised' confirmation again, or retry without them."
    )
    assert await count(db_engine, Scan) == 1  # nothing was started


async def test_retrying_with_an_empty_body_is_still_a_409(
    client, db_engine, no_dispatch, all_tools
):
    headers, target = await make_target(client, "r-409-empty")
    scan = await active_scan(client, db_engine, target, headers)
    resp = await client.post(f"/scans/{scan['id']}/retry", json={}, headers={**headers, **who()})
    assert resp.status_code == 409


async def test_retrying_without_the_active_tools(client, db_engine, no_dispatch, all_tools):
    headers, target = await make_target(client, "r-drop")
    scan = await active_scan(client, db_engine, target, headers, port_scan=True, speed="gentle")
    resp = await client.post(
        f"/scans/{scan['id']}/retry",
        json={"drop_active_tools": True},
        headers={**headers, **who("bob")},
    )
    assert resp.status_code == 201, resp.text
    new = resp.json()
    assert new["requested_by"] == "bob"
    assert new["options"]["dir_bruteforce"] is False
    assert new["options"]["port_scan"] is False
    assert new["options"]["all_ports"] is False
    assert new["options"]["speed"] == "gentle"  # everything else is carried over
    assert (
        await client.get(f"/scans/{new['id']}/authorisation", headers=headers)
    ).status_code == 404
    # the old scan keeps its own record
    assert (
        await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)
    ).status_code == 200


async def test_drop_wins_over_a_supplied_confirmation(client, db_engine, no_dispatch, all_tools):
    headers, target = await make_target(client, "r-drop-wins")
    scan = await active_scan(client, db_engine, target, headers)
    resp = await client.post(
        f"/scans/{scan['id']}/retry",
        json={"drop_active_tools": True, "authorisation": confirm()},
        headers={**headers, **who()},
    )
    assert resp.status_code == 201
    assert resp.json()["options"]["dir_bruteforce"] is False
    assert await count(db_engine, ScanAuthorisation) == 1


async def test_a_reconfirmed_retry_stores_a_new_record_pointing_at_the_old_scan(
    client, db_engine, no_dispatch, all_tools
):
    headers, target = await make_target(client, "r-again")
    scan = await active_scan(
        client, db_engine, target, headers, port_scan=True, recon_profile="full"
    )
    resp = await client.post(
        f"/scans/{scan['id']}/retry",
        json={"authorisation": confirm(client_name="Acme Holdings")},
        headers={**headers, **who("bob")},  # a different person than the original
    )
    assert resp.status_code == 201, resp.text
    new = resp.json()
    assert new["requested_by"] == "bob"
    assert new["options"]["dir_bruteforce"] is True
    assert new["options"]["port_scan"] is True
    rec = (await client.get(f"/scans/{new['id']}/authorisation", headers=headers)).json()
    assert rec["username"] == "bob"
    assert rec["client_name"] == "Acme Holdings"
    assert rec["carried_over_from_scan_id"] == scan["id"]
    assert rec["tools"] == ["dir_bruteforce", "port_scan"]
    assert rec["scan_id"] == new["id"]
    old = (await client.get(f"/scans/{scan['id']}/authorisation", headers=headers)).json()
    assert old["username"] == "alice"
    assert old["carried_over_from_scan_id"] is None


async def test_a_reconfirmed_retry_is_validated_like_a_new_scan(
    client, db_engine, no_dispatch, all_tools
):
    headers, target = await make_target(client, "r-validated")
    scan = await active_scan(client, db_engine, target, headers)
    url = f"/scans/{scan['id']}/retry"

    no_identity = await client.post(url, json={"authorisation": confirm()}, headers=headers)
    assert no_identity.status_code == 403

    not_accepted = await client.post(
        url, json={"authorisation": confirm(accepted=False)}, headers={**headers, **who()}
    )
    assert not_accepted.status_code == 422

    stale = await client.post(
        url,
        json={"authorisation": confirm(statement_version="0")},
        headers={**headers, **who()},
    )
    assert stale.status_code == 409
    assert "Reload the page" in stale.json()["detail"]
    assert await count(db_engine, Scan) == 1


async def test_a_retry_of_an_all_ports_scan_needs_the_second_confirmation(
    client, db_engine, no_dispatch, all_tools
):
    headers, target = await make_target(client, "r-allports")
    scan = (
        await start(
            client,
            target,
            {**headers, **who()},
            port_scan=True,
            all_ports=True,
            recon_profile="full",
            authorisation=confirm(all_ports_confirmed=True),
        )
    ).json()
    await set_state(db_engine, scan["id"], ScanState.FAILED)
    url = f"/scans/{scan['id']}/retry"
    resp = await client.post(
        url,
        json={"authorisation": confirm(all_ports_confirmed=False)},
        headers={**headers, **who()},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "Scanning all 65,535 ports needs its own confirmation."
    ok = await client.post(
        url, json={"authorisation": confirm(all_ports_confirmed=True)}, headers={**headers, **who()}
    )
    assert ok.status_code == 201
    assert ok.json()["options"]["all_ports"] is True


async def test_retry_of_an_unfinished_scan_is_still_a_409_before_any_tool_logic(
    client, db_engine, no_dispatch, all_tools
):
    headers, target = await make_target(client, "r-running")
    scan = await active_scan(client, db_engine, target, headers, state=ScanState.CRAWLING)
    resp = await client.post(
        f"/scans/{scan['id']}/retry",
        json={"authorisation": confirm()},
        headers={**headers, **who()},
    )
    assert resp.status_code == 409
    assert "still running" in resp.json()["detail"]


# --- Cancel --------------------------------------------------------------------


async def test_cancelling_a_queued_scan_closes_it_at_once(client, db_engine, no_dispatch, redis_db):
    headers, target = await make_target(client, "x-queued")
    scan = (await start(client, target, headers)).json()
    resp = await client.post(f"/scans/{scan['id']}/cancel", headers={**headers, **who("dana")})
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["state"] == "cancelled"
    assert body["fail_reason"] == "Cancelled by dana before it started."
    assert body["finished_at"] is not None
    # persisted, not just echoed
    got = (await client.get(f"/scans/{scan['id']}", headers=headers)).json()
    assert got["state"] == "cancelled"
    assert got["fail_reason"] == "Cancelled by dana before it started."


async def test_cancel_works_without_an_identity_and_says_unknown(client, no_dispatch, redis_db):
    headers, target = await make_target(client, "x-anon")
    scan = (await start(client, target, headers)).json()
    resp = await client.post(f"/scans/{scan['id']}/cancel", headers=headers)
    assert resp.status_code == 202
    assert resp.json()["fail_reason"] == "Cancelled by unknown before it started."


async def test_cancelling_a_running_scan_sets_the_flag_and_leaves_the_state_to_the_worker(
    client, db_engine, no_dispatch, redis_db
):
    headers, target = await make_target(client, "x-running")
    scan = (await start(client, target, headers)).json()
    await set_state(db_engine, scan["id"], ScanState.CRAWLING)
    resp = await client.post(f"/scans/{scan['id']}/cancel", headers={**headers, **who("dana")})
    assert resp.status_code == 202
    assert resp.json()["state"] == "crawling"  # the worker closes it
    key = f"sentinel:scan-cancel:{scan['id']}"
    assert (await redis_db.get(key)) == b"dana"
    ttl = await redis_db.ttl(key)
    assert 80000 < ttl <= 86400


async def test_cancelling_a_running_scan_without_identity_records_unknown(
    client, db_engine, no_dispatch, redis_db
):
    headers, target = await make_target(client, "x-running-anon")
    scan = (await start(client, target, headers)).json()
    await set_state(db_engine, scan["id"], ScanState.RECON)
    assert (await client.post(f"/scans/{scan['id']}/cancel", headers=headers)).status_code == 202
    assert (await redis_db.get(f"sentinel:scan-cancel:{scan['id']}")) == b"unknown"


async def test_cancelling_a_paused_scan_closes_it_directly(
    client, db_engine, no_dispatch, redis_db
):
    headers, target = await make_target(client, "x-paused")
    scan = (await start(client, target, headers)).json()
    await set_state(db_engine, scan["id"], ScanState.PAUSED)
    resp = await client.post(f"/scans/{scan['id']}/cancel", headers={**headers, **who("dana")})
    assert resp.status_code == 202
    assert resp.json()["state"] == "cancelled"
    assert resp.json()["fail_reason"] == "Cancelled by dana while paused."


@pytest.mark.parametrize(
    "state",
    [
        ScanState.COMPLETE,
        ScanState.FAILED,
        ScanState.CANCELLED,
        ScanState.BLOCKED_UNVERIFIED,
        ScanState.FAILED_AUTH,
    ],
)
async def test_cancelling_a_finished_scan_is_a_409_and_sets_no_flag(
    client, db_engine, no_dispatch, redis_db, state
):
    headers, target = await make_target(client, f"x-done-{state.value.replace('_', '-')}")
    scan = (await start(client, target, headers)).json()
    await set_state(db_engine, scan["id"], state)
    resp = await client.post(f"/scans/{scan['id']}/cancel", headers=headers)
    assert resp.status_code == 409
    assert "already finished" in resp.json()["detail"]
    assert await redis_db.get(f"sentinel:scan-cancel:{scan['id']}") is None


async def test_cancelling_twice_is_a_409_the_second_time(client, no_dispatch, redis_db):
    headers, target = await make_target(client, "x-twice")
    scan = (await start(client, target, headers)).json()
    assert (await client.post(f"/scans/{scan['id']}/cancel", headers=headers)).status_code == 202
    assert (await client.post(f"/scans/{scan['id']}/cancel", headers=headers)).status_code == 409


async def test_cancel_is_scoped_to_the_callers_org(client, no_dispatch, redis_db):
    headers, target = await make_target(client, "x-org-a")
    other_headers, _ = await make_target(client, "x-org-b")
    scan = (await start(client, target, headers)).json()
    assert (
        await client.post(f"/scans/{scan['id']}/cancel", headers=other_headers)
    ).status_code == 404
    assert (await client.get(f"/scans/{scan['id']}", headers=headers)).json()["state"] == "queued"


async def test_cancel_reports_a_queue_outage_instead_of_pretending(
    client, db_engine, no_dispatch, monkeypatch
):
    headers, target = await make_target(client, "x-redis-down")
    scan = (await start(client, target, headers)).json()
    await set_state(db_engine, scan["id"], ScanState.CRAWLING)
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    resp = await client.post(f"/scans/{scan['id']}/cancel", headers=headers)
    assert resp.status_code == 503
    assert "cancel request" in resp.json()["detail"]


async def test_a_queued_cancel_still_succeeds_when_the_flag_cannot_be_written(
    client, no_dispatch, monkeypatch
):
    headers, target = await make_target(client, "x-queued-redis-down")
    scan = (await start(client, target, headers)).json()
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    resp = await client.post(f"/scans/{scan['id']}/cancel", headers=headers)
    assert resp.status_code == 202
    assert resp.json()["state"] == "cancelled"

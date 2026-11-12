"""The flagship test for M2 slice 1: the real multi-tenant fixture app
(fixtures/multi_tenant_app.py), a real Postgres, real Redis, and a real
headless browser, run through the actual pipeline — auth establishing,
crawling, access control, and the Phase 9 verification gate — exactly as
docs/05-v1-roadmap.md's M2 exit criterion describes: "on the custom
multi-tenant fixture, we find every planted IDOR/authz bug and flag zero
known-good endpoints."

alice (tenant acme) and bob (tenant beta) each have a private note; the
fixture's one planted bug is that /notes/{id} never checks ownership, so
each one's note is a horizontal IDOR waiting to be found via the other's
persona. carol (tenant acme, admin) can reach /admin/dashboard, which
*is* properly protected — the same run must produce zero findings there,
across all three boundaries that apply to it (vertical from alice and bob,
horizontal from bob, anonymous from all).
"""

from __future__ import annotations

from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_db.enums import CredentialKind, FindingConfidence, FindingSeverity
from sentinel_db.models import Credential, Finding, Organization, Persona, Scan, Target
from sentinel_worker_app.config import Settings
from sentinel_worker_app.scan_runner import (
    _run_access_control,
    _run_auth_establishing,
    _run_crawling,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload

MASTER_KEY = b"pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68="

_USERS = [
    # username, password, trust_rank, tenant_key, role, canary_tokens
    ("alice", "alice-pw-093", 1, "acme", "member", ["canary-alice-9f3d1"]),
    ("bob", "bob-pw-471", 1, "beta", "member", ["canary-bob-7a2c4"]),
    # carol has no tenant_key at all — an org-wide admin, not scoped to
    # either tenant — so she's cleanly outside the horizontal boundary in
    # both directions; only vertical/anonymous apply to her admin request.
    # (If she shared a tenant with either member, bob's note would also
    # leak to her — a *third*, equally real instance of the same bug, not
    # a bug in the checker — but that would muddy this test's one-bug
    # narrative, so the fixture keeps her isolated.)
    ("carol", "carol-pw-582", 2, None, "admin", []),
]


def _settings() -> Settings:
    return Settings(kms_master_key=MASTER_KEY.decode())


def _recipe(server: str, username: str) -> dict:
    return {
        "start_url": f"{server}/login",
        "steps": [
            {"action": "fill", "selector": "input[name=username]", "value": username},
            {"action": "fill_secret", "selector": "input[name=password]", "credential_ref": "pw"},
            {"action": "click", "selector": "button[type=submit]"},
        ],
        "success_assertion": {"kind": "url_contains", "value": "/dashboard"},
    }


async def _make_fixture(session, *, server: str):
    crypto = EnvelopeCrypto(LocalMasterKeyProvider([MASTER_KEY]))
    data_key = crypto.generate_data_key()

    org = Organization(
        name="Acme", slug="acme-access-control", wrapped_data_key=crypto.wrap_data_key(data_key)
    )
    session.add(org)
    await session.flush()

    root_domain = server.split("://", 1)[1].split(":")[0]
    target = Target(
        organization_id=org.id,
        root_domain=root_domain,
        display_name="Multi-tenant App",
        ownership_verified=True,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()

    scan = Scan(target_id=target.id)
    session.add(scan)
    await session.flush()

    for username, password, trust_rank, tenant_key, role, canary_tokens in _USERS:
        credential = Credential(
            kind=CredentialKind.PASSWORD, ciphertext=crypto.encrypt(data_key, password.encode())
        )
        session.add(credential)
        await session.flush()

        session.add(
            Persona(
                target_id=target.id,
                label=username,
                role_name=role,
                trust_rank=trust_rank,
                tenant_key=tenant_key,
                credential_id=credential.id,
                login_recipe=_recipe(server, username),
                canary_tokens=canary_tokens,
            )
        )
        await session.flush()

    await session.commit()

    reloaded = (
        (
            await session.execute(
                select(Persona)
                .where(Persona.target_id == target.id)
                .options(selectinload(Persona.credential))
            )
        )
        .scalars()
        .all()
    )
    personas = {p.label: p for p in reloaded}

    return org, target, scan, personas


async def test_horizontal_idor_confirmed_and_admin_endpoint_stays_clean(
    db_engine, redis_client, browser, multi_tenant_app_server
):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        org, target, scan, personas = await _make_fixture(session, server=multi_tenant_app_server)
        all_personas = [personas["alice"], personas["bob"], personas["carol"]]

        auth_stats, sessions = await _run_auth_establishing(
            scan=scan,
            target=target,
            org=org,
            scope_rules=[],
            configured_personas=all_personas,
            settings=_settings(),
            redis_client=redis_client,
            browser=browser,
            oracle_probe_url=f"{multi_tenant_app_server}/dashboard",
        )
        assert auth_stats["personas_available"] == 3, sessions

        surfaces = await _run_crawling(
            target=target,
            scope_rules=[],
            configured_personas=all_personas,
            in_memory_sessions=sessions,
            redis_client=redis_client,
            browser=browser,
            root_url=f"{multi_tenant_app_server}/",
        )

        root_domain = multi_tenant_app_server.split("://", 1)[1].split(":")[0]
        stats, findings, transcript_records = await _run_access_control(
            scan=scan,
            target=target,
            scope_rules=[],
            surfaces=surfaces,
            personas=all_personas,
            in_memory_sessions=sessions,
            settings=_settings(),
            redis_client=redis_client,
            target_host=root_domain,
        )

        # The one planted bug, caught in both directions — and nothing else
        # confirmed. (The crawl also records each persona's own visit to
        # "/" as an observed request, and replaying that across identities
        # is honestly AMBIGUOUS — a personalized homepage legitimately
        # differs per viewer, and without Layer 4/a canary on that page the
        # oracle correctly declines to guess rather than reporting either a
        # false positive or a false "all clear".)
        assert stats.candidates_found == 2
        assert stats.confirmed == 2
        assert stats.probable == 0
        assert stats.ambiguous_skipped > 0

        session.add_all(transcript_records)
        session.add_all(findings)
        await session.commit()

        persisted = (
            (await session.execute(select(Finding).where(Finding.scan_id == scan.id)))
            .scalars()
            .all()
        )
        assert len(persisted) == 2
        assert {f.rule_id for f in persisted} == {"authz.horizontal"}
        assert all(f.confidence == FindingConfidence.CONFIRMED for f in persisted)
        assert all(f.severity == FindingSeverity.HIGH for f in persisted)
        for finding in persisted:
            assert finding.verification is not None
            assert finding.verification.passed is True
            assert finding.verification.reproduced_count >= 2
            assert len(finding.evidence) == 1

        pairs = {
            (f.reproduction["requesting_persona_id"], f.reproduction["denied_persona_id"])
            for f in persisted
        }
        assert pairs == {
            (str(personas["alice"].id), str(personas["bob"].id)),
            (str(personas["bob"].id), str(personas["alice"].id)),
        }

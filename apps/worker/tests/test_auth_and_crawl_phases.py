"""_run_auth_establishing and _run_crawling against a real Postgres, real
Redis, real headless browser, and the real login-gated fixture app
(fixtures/persona_app.py) — the actual M1 pipeline end to end, short of the
DNS-bound recon phase (see conftest.py's module docstring for why that
piece alone stays out of scope here).
"""

from __future__ import annotations

from sentinel_core.crypto import EnvelopeCrypto, LocalMasterKeyProvider
from sentinel_db.enums import CredentialKind
from sentinel_db.models import Credential, Organization, Persona, Scan, Target
from sentinel_worker_app.config import Settings
from sentinel_worker_app.scan_runner import _run_auth_establishing, _run_crawling
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import selectinload

MASTER_KEY = b"pqZYJLYj1FhYOPuvYGh7t-j51JPqxF6e6BEUnBEkY68="

VALID_RECIPE = {
    "start_url": "PLACEHOLDER",  # filled in per-test with the real fixture URL
    "steps": [
        {"action": "fill", "selector": "input[name=username]", "value": "alice"},
        {"action": "fill_secret", "selector": "input[name=password]", "credential_ref": "pw"},
        {"action": "click", "selector": "button[type=submit]"},
    ],
    "success_assertion": {"kind": "url_contains", "value": "/dashboard"},
}


def _settings() -> Settings:
    return Settings(kms_master_key=MASTER_KEY.decode())


async def _make_org_target_persona(
    session, *, recipe: dict | None, root_domain: str, secret: str = "correct-horse-battery-staple"
):
    # `root_domain` must be the fixture server's real host (e.g. "127.0.0.1")
    # so ScopeGuard actually permits requests to it — the guard has no
    # notion of "this fake domain and that real IP are the same target",
    # nor should it (docs/06-safety-legal-abuse.md §2).
    crypto = EnvelopeCrypto(LocalMasterKeyProvider([MASTER_KEY]))
    data_key = crypto.generate_data_key()

    org = Organization(
        name="Acme", slug="acme-auth-crawl", wrapped_data_key=crypto.wrap_data_key(data_key)
    )
    session.add(org)
    await session.flush()

    target = Target(
        organization_id=org.id,
        root_domain=root_domain,
        display_name="Persona App",
        ownership_verified=True,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()

    credential = Credential(
        kind=CredentialKind.PASSWORD, ciphertext=crypto.encrypt(data_key, secret.encode())
    )
    session.add(credential)
    await session.flush()

    persona = Persona(
        target_id=target.id,
        label="Member",
        role_name="member",
        credential_id=credential.id,
        login_recipe=recipe,
    )
    session.add(persona)
    await session.flush()

    scan = Scan(target_id=target.id)
    session.add(scan)
    await session.flush()
    await session.commit()

    # Mirrors how scan_runner.run_scan actually loads personas
    # (.options(selectinload(Persona.credential))) — accessing the
    # relationship lazily here, outside any awaited session call, would hit
    # AsyncSession's MissingGreenlet guard.
    persona = (
        await session.execute(
            select(Persona)
            .where(Persona.id == persona.id)
            .options(selectinload(Persona.credential))
        )
    ).scalar_one()

    return org, target, persona, scan


async def test_auth_establishing_succeeds_and_persists_session(
    db_engine, redis_client, browser, persona_app_server
):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        recipe = {**VALID_RECIPE, "start_url": f"{persona_app_server}/login"}
        root_domain = persona_app_server.split("://", 1)[1].split(":")[0]
        org, target, persona, scan = await _make_org_target_persona(
            session, recipe=recipe, root_domain=root_domain
        )

        stats, sessions = await _run_auth_establishing(
            scan=scan,
            target=target,
            org=org,
            scope_rules=[],
            configured_personas=[persona],
            settings=_settings(),
            redis_client=redis_client,
            browser=browser,
            oracle_probe_url=f"{persona_app_server}/api/me",
        )

        assert stats["personas_available"] == 1
        assert persona.is_available is True
        assert persona.unavailable_reason is None
        assert persona.session_state_ciphertext is not None
        assert persona.session_oracle is not None
        assert persona.session_oracle["signal"] == "status_code"
        assert str(persona.id) in sessions
        assert "cookies" in sessions[str(persona.id)]


async def test_auth_establishing_records_failure_for_wrong_password(
    db_engine, redis_client, browser, persona_app_server
):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        recipe = {**VALID_RECIPE, "start_url": f"{persona_app_server}/login"}
        root_domain = persona_app_server.split("://", 1)[1].split(":")[0]
        org, target, persona, scan = await _make_org_target_persona(
            session, recipe=recipe, root_domain=root_domain, secret="totally-wrong-password"
        )

        stats, sessions = await _run_auth_establishing(
            scan=scan,
            target=target,
            org=org,
            scope_rules=[],
            configured_personas=[persona],
            settings=_settings(),
            redis_client=redis_client,
            browser=browser,
            oracle_probe_url=f"{persona_app_server}/api/me",
        )

        assert stats["personas_available"] == 0
        assert persona.is_available is False
        assert "Login replay failed" in persona.unavailable_reason
        assert sessions == {}


async def test_crawling_anonymous_and_authenticated_see_different_surfaces(
    db_engine, redis_client, browser, persona_app_server
):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        recipe = {**VALID_RECIPE, "start_url": f"{persona_app_server}/login"}
        root_domain = persona_app_server.split("://", 1)[1].split(":")[0]
        org, target, persona, scan = await _make_org_target_persona(
            session, recipe=recipe, root_domain=root_domain
        )

        _, sessions = await _run_auth_establishing(
            scan=scan,
            target=target,
            org=org,
            scope_rules=[],
            configured_personas=[persona],
            settings=_settings(),
            redis_client=redis_client,
            browser=browser,
            oracle_probe_url=f"{persona_app_server}/api/me",
        )
        assert sessions  # sanity: login actually worked

        surfaces = await _run_crawling(
            target=target,
            scope_rules=[],
            configured_personas=[persona],
            in_memory_sessions=sessions,
            redis_client=redis_client,
            browser=browser,
            root_url=f"{persona_app_server}/",
        )

        by_persona = {s.persona_id: s for s in surfaces}
        assert "anonymous" in by_persona
        assert str(persona.id) in by_persona

        anon_templates = {e.path_template for e in by_persona["anonymous"].endpoints}
        member_templates = {e.path_template for e in by_persona[str(persona.id)].endpoints}

        # The whole point of this product: the authenticated persona reaches
        # pages the anonymous crawl never even sees a link to.
        assert "/dashboard" not in anon_templates
        assert "/settings" not in anon_templates
        assert "/dashboard" in member_templates
        assert "/settings" in member_templates

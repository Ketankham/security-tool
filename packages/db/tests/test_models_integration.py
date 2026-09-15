"""Integration tests against a real Postgres. These exercise things a pure
unit test can't: actual FK/index DDL, JSONB round-tripping, and — the one
that matters most — that the CONFIRMED-requires-Verification invariant
(models/finding.py) is enforced by the real database session, not just in
theory (docs/adr/0001-engine-split-ai-vs-deterministic.md).
"""

from __future__ import annotations

import pytest
from sentinel_db.enums import FindingConfidence, FindingSeverity, OwnershipVerificationMethod
from sentinel_db.models import Finding, Organization, Scan, Target, Verification

pytestmark = pytest.mark.integration


async def _make_org_target_scan(session):
    org = Organization(name="Acme", slug="acme", wrapped_data_key=b"wrapped-key-bytes")
    session.add(org)
    await session.flush()

    target = Target(
        organization_id=org.id,
        root_domain="acme.test",
        display_name="Acme App",
        ownership_verified=True,
        ownership_verification_method=OwnershipVerificationMethod.DNS_TXT,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()

    scan = Scan(target_id=target.id)
    session.add(scan)
    await session.flush()
    return org, target, scan


async def test_target_is_scannable_reflects_both_gates(session_factory):
    async with session_factory() as session:
        org, target, _ = await _make_org_target_scan(session)
        assert target.is_scannable

        target.authorization_accepted = False
        assert not target.is_scannable


async def test_probable_finding_persists_without_verification(session_factory):
    async with session_factory() as session:
        _, _, scan = await _make_org_target_scan(session)

        finding = Finding(
            scan_id=scan.id,
            fingerprint=Finding.compute_fingerprint(
                rule_id="authz.horizontal.idor",
                endpoint_template="/api/invoices/{id}",
                param="id",
                persona_pair="admin->member",
            ),
            rule_id="authz.horizontal.idor",
            title="Invoice IDOR",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.PROBABLE,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
        )
        session.add(finding)
        await session.commit()  # should NOT raise
        assert finding.id is not None


async def test_confirmed_finding_without_verification_is_rejected(session_factory):
    async with session_factory() as session:
        _, _, scan = await _make_org_target_scan(session)

        finding = Finding(
            scan_id=scan.id,
            fingerprint=Finding.compute_fingerprint(
                rule_id="authz.horizontal.idor",
                endpoint_template="/api/invoices/{id}",
                param="id",
                persona_pair="admin->member",
            ),
            rule_id="authz.horizontal.idor",
            title="Invoice IDOR",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.CONFIRMED,  # no Verification attached
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
        )
        session.add(finding)
        with pytest.raises(ValueError, match="CONFIRMED"):
            await session.commit()


async def test_confirmed_finding_with_insufficient_reproductions_is_rejected(session_factory):
    async with session_factory() as session:
        _, _, scan = await _make_org_target_scan(session)

        finding = Finding(
            scan_id=scan.id,
            fingerprint=Finding.compute_fingerprint(
                rule_id="session.no_invalidation_on_logout",
                endpoint_template="/api/me",
                param="",
                persona_pair="admin->admin",
            ),
            rule_id="session.no_invalidation_on_logout",
            title="Session survives logout",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.CONFIRMED,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
            verification=Verification(reproduced_count=1, attempted_count=1, passed=True),
        )
        session.add(finding)
        with pytest.raises(ValueError, match="CONFIRMED"):
            await session.commit()


async def test_confirmed_finding_with_passing_verification_persists(session_factory):
    async with session_factory() as session:
        _, _, scan = await _make_org_target_scan(session)

        finding = Finding(
            scan_id=scan.id,
            fingerprint=Finding.compute_fingerprint(
                rule_id="session.no_invalidation_on_logout",
                endpoint_template="/api/me",
                param="",
                persona_pair="admin->admin",
            ),
            rule_id="session.no_invalidation_on_logout",
            title="Session survives logout",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.CONFIRMED,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
            verification=Verification(reproduced_count=2, attempted_count=2, passed=True),
        )
        session.add(finding)
        await session.commit()  # should NOT raise
        assert finding.verification.satisfies_confirmed

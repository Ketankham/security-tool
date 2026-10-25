"""The replay matrix's deny-set logic (docs/03 §4.1–4.2): who should be
refused a given actor's request, and under which boundary."""

from __future__ import annotations

from sentinel_checks.authz import personas_that_should_be_denied
from sentinel_checks.authz.models import AuthzBoundary, PersonaProfile

ANON = PersonaProfile.anonymous()
ADMIN_A = PersonaProfile(
    id="admin-a", label="Admin A", role_name="admin", trust_rank=30, tenant_key="A"
)
MEMBER_A = PersonaProfile(
    id="member-a", label="Member A", role_name="member", trust_rank=10, tenant_key="A"
)
ADMIN_B = PersonaProfile(
    id="admin-b", label="Admin B", role_name="admin", trust_rank=30, tenant_key="B"
)
MEMBER_B = PersonaProfile(
    id="member-b", label="Member B", role_name="member", trust_rank=10, tenant_key="B"
)

ALL = [ANON, ADMIN_A, MEMBER_A, ADMIN_B, MEMBER_B]


def _deny_map(actor):
    return {s.id: b for s, b in personas_that_should_be_denied(actor, ALL)}


def test_admin_request_denies_anon_lower_role_and_other_tenant():
    m = _deny_map(ADMIN_A)
    assert m["anonymous"] is AuthzBoundary.ANONYMOUS
    assert m["member-a"] is AuthzBoundary.VERTICAL  # same tenant, lower role
    assert m["admin-b"] is AuthzBoundary.HORIZONTAL  # other tenant, same role
    assert m["member-b"] is AuthzBoundary.HORIZONTAL  # other tenant wins over vertical
    assert "admin-a" not in m  # never denies itself


def test_member_request_does_not_deny_the_admin_above_it():
    m = _deny_map(MEMBER_A)
    # A higher-privileged same-tenant admin is expected to have access.
    assert "admin-a" not in m
    assert m["anonymous"] is AuthzBoundary.ANONYMOUS
    assert m["member-b"] is AuthzBoundary.HORIZONTAL
    assert m["admin-b"] is AuthzBoundary.HORIZONTAL


def test_anonymous_actor_has_no_deny_set():
    # Anonymous has no protected resource others could wrongly reach.
    assert personas_that_should_be_denied(ANON, ALL) == []


def test_cross_tenant_ranked_above_vertical():
    # member-b is both a different tenant and a lower rank than admin-a;
    # it must be reported as horizontal (tenant isolation), not vertical.
    m = _deny_map(ADMIN_A)
    assert m["member-b"] is AuthzBoundary.HORIZONTAL


def test_untenanted_personas_fall_back_to_vertical():
    # When tenancy isn't modelled (tenant_key None), only role rank applies.
    admin = PersonaProfile(id="a", label="A", role_name="admin", trust_rank=30)
    member = PersonaProfile(id="m", label="M", role_name="member", trust_rank=10)
    m = {s.id: b for s, b in personas_that_should_be_denied(admin, [admin, member, ANON])}
    assert m["m"] is AuthzBoundary.VERTICAL
    assert m["anonymous"] is AuthzBoundary.ANONYMOUS

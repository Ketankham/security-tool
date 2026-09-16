from sentinel_checks.access_control import ANONYMOUS_PERSONA_ID, PersonaIdentity
from sentinel_checks.access_control.replay_matrix import personas_that_should_be_denied

ADMIN = PersonaIdentity(persona_id="admin", trust_rank=2, tenant_key="tenant-a")
MEMBER_A = PersonaIdentity(persona_id="member-a", trust_rank=1, tenant_key="tenant-a")
MEMBER_B = PersonaIdentity(persona_id="member-b", trust_rank=1, tenant_key="tenant-b")
VIEWER_A = PersonaIdentity(persona_id="viewer-a", trust_rank=0, tenant_key="tenant-a")


def test_vertical_boundary_lower_trust_rank_should_be_denied():
    denied = personas_that_should_be_denied(ADMIN, [ADMIN, MEMBER_A, MEMBER_B])
    denied_ids = {p.persona_id: boundaries for p, boundaries in denied}
    assert "vertical" in denied_ids["member-a"]
    assert "vertical" in denied_ids["member-b"]


def test_horizontal_boundary_different_tenant_should_be_denied():
    denied = personas_that_should_be_denied(MEMBER_A, [MEMBER_A, MEMBER_B, ADMIN])
    denied_ids = {p.persona_id: boundaries for p, boundaries in denied}
    assert "horizontal" in denied_ids["member-b"]
    # ADMIN is same tenant and higher trust_rank — no boundary applies.
    assert "admin" not in denied_ids


def test_same_trust_rank_same_tenant_is_not_denied():
    peer = PersonaIdentity(persona_id="member-a2", trust_rank=1, tenant_key="tenant-a")
    denied = personas_that_should_be_denied(MEMBER_A, [MEMBER_A, peer])
    # No boundary applies to the peer — only the synthetic anonymous entry,
    # added unconditionally for any trust_rank > 0.
    denied_ids = {p.persona_id: boundaries for p, boundaries in denied}
    assert "member-a2" not in denied_ids
    assert denied_ids[ANONYMOUS_PERSONA_ID] == ["anonymous"]


def test_anonymous_boundary_added_for_any_authenticated_persona():
    denied = personas_that_should_be_denied(MEMBER_A, [MEMBER_A])
    denied_ids = {p.persona_id: boundaries for p, boundaries in denied}
    assert denied_ids[ANONYMOUS_PERSONA_ID] == ["anonymous"]


def test_anonymous_requester_has_nothing_to_deny():
    anon = PersonaIdentity(persona_id=ANONYMOUS_PERSONA_ID, trust_rank=0, tenant_key=None)
    assert personas_that_should_be_denied(anon, [MEMBER_A, ADMIN]) == []


def test_persona_that_is_both_vertical_and_horizontal_gets_both_boundaries():
    lower_other_tenant = PersonaIdentity(persona_id="viewer-b", trust_rank=0, tenant_key="tenant-b")
    denied = personas_that_should_be_denied(ADMIN, [ADMIN, lower_other_tenant])
    denied_by_id = {p.persona_id: boundaries for p, boundaries in denied}
    assert set(denied_by_id["viewer-b"]) == {"vertical", "horizontal"}


def test_null_tenant_key_never_triggers_horizontal():
    no_tenant = PersonaIdentity(persona_id="solo", trust_rank=1, tenant_key=None)
    other_no_tenant = PersonaIdentity(persona_id="solo-2", trust_rank=1, tenant_key=None)
    denied = personas_that_should_be_denied(no_tenant, [no_tenant, other_no_tenant])
    # No vertical (same rank), no horizontal (either side lacks a tenant_key), no anonymous entry
    # beyond the synthetic one added for any trust_rank > 0.
    denied_ids = {p.persona_id: boundaries for p, boundaries in denied}
    assert "solo-2" not in denied_ids
    assert denied_ids[ANONYMOUS_PERSONA_ID] == ["anonymous"]

"""The layered access oracle's FP/FN table (docs/03 §4.4). This is the
product's central claim expressed as assertions: every row is either a real
bypass we must catch or a benign case we must not flag."""

from __future__ import annotations

from sentinel_checks.authz import access_oracle
from sentinel_checks.authz.models import AccessVerdict, OracleLayer, OracleResponse

ACTOR = OracleResponse(
    status_code=200, text='{"id": 1, "secret": "CANARY-abc123", "data": "x" * 0}'
)


def _resp(status, text=""):
    return OracleResponse(status_code=status, text=text)


def test_subject_denied_by_403_is_not_a_finding():
    r = access_oracle(
        actor=ACTOR, subject=_resp(403, "forbidden"), actor_canaries=["CANARY-abc123"]
    )
    assert r.verdict is AccessVerdict.DENIED
    assert r.layer is OracleLayer.STATUS


def test_subject_denied_by_401():
    r = access_oracle(actor=ACTOR, subject=_resp(401), actor_canaries=[])
    assert r.verdict is AccessVerdict.DENIED


def test_subject_redirected_to_login_is_not_a_finding():
    # A 3xx to a denied identity is a redirect to login/error, not access.
    r = access_oracle(actor=ACTOR, subject=_resp(302, ""), actor_canaries=[])
    assert r.verdict is AccessVerdict.DENIED
    assert r.layer is OracleLayer.STATUS


def test_canary_hit_is_deterministic_unauthorized_access():
    subject = _resp(200, 'you can see {"secret": "CANARY-abc123"} oops')
    r = access_oracle(actor=ACTOR, subject=subject, actor_canaries=["CANARY-abc123"])
    assert r.verdict is AccessVerdict.UNAUTHORIZED_ACCESS
    assert r.layer is OracleLayer.CANARY
    assert r.deterministic
    assert r.canary_hit == "CANARY-abc123"


def test_identical_body_without_canary_is_treated_as_public():
    # Same bytes to both identities, no canary -> identity-independent resource.
    body = '{"status": "ok", "version": "1.2.3"}'
    r = access_oracle(actor=_resp(200, body), subject=_resp(200, body), actor_canaries=[])
    assert r.verdict is AccessVerdict.DENIED
    assert r.layer is OracleLayer.STRUCTURE


def test_near_empty_subject_body_is_denied():
    r = access_oracle(actor=_resp(200, "x" * 500), subject=_resp(200, "[]"), actor_canaries=[])
    assert r.verdict is AccessVerdict.DENIED
    assert r.layer is OracleLayer.STRUCTURE


def test_much_smaller_subject_body_is_denied():
    r = access_oracle(
        actor=_resp(200, "x" * 1000), subject=_resp(200, "x" * 100), actor_canaries=[]
    )
    assert r.verdict is AccessVerdict.DENIED
    assert r.layer is OracleLayer.STRUCTURE


def test_substantial_similar_body_without_canary_is_probable_semantic():
    actor = _resp(200, "A" * 400)
    subject = _resp(200, "B" * 390)  # similar size, different content, no canary
    r = access_oracle(actor=actor, subject=subject, actor_canaries=["CANARY-abc123"])
    assert r.verdict is AccessVerdict.UNAUTHORIZED_ACCESS
    assert r.layer is OracleLayer.SEMANTIC
    assert not r.deterministic  # caps the finding at probable


def test_no_baseline_when_actor_not_2xx():
    r = access_oracle(actor=_resp(500, "err"), subject=_resp(200, "x" * 200), actor_canaries=[])
    assert r.verdict is AccessVerdict.INCONCLUSIVE


def test_canary_wins_even_when_sizes_differ():
    # A canary hit must beat the size-based negative filters.
    actor = _resp(200, "x" * 1000)
    subject = _resp(200, "CANARY-abc123")  # tiny, but contains the canary
    r = access_oracle(actor=actor, subject=subject, actor_canaries=["CANARY-abc123"])
    assert r.verdict is AccessVerdict.UNAUTHORIZED_ACCESS
    assert r.layer is OracleLayer.CANARY

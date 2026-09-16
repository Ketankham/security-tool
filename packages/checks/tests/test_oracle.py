import json

from sentinel_checks.access_control import OracleVerdict
from sentinel_checks.access_control.oracle import judge


def test_layer1_denied_401_is_not_a_finding():
    verdict, _ = judge(p_status=200, p_body=b"secret", q_status=401, q_body=b"", p_canary_tokens=())
    assert verdict == OracleVerdict.NOT_A_FINDING


def test_layer1_denied_403_is_not_a_finding():
    verdict, _ = judge(
        p_status=200, p_body=b"secret", q_status=403, q_body=b"forbidden", p_canary_tokens=()
    )
    assert verdict == OracleVerdict.NOT_A_FINDING


def test_layer2_empty_json_list_is_not_a_finding():
    p_body = json.dumps([{"id": 1, "note": "P's private note"}]).encode()
    q_body = json.dumps([]).encode()
    verdict, _ = judge(p_status=200, p_body=p_body, q_status=200, q_body=q_body, p_canary_tokens=())
    assert verdict == OracleVerdict.NOT_A_FINDING


def test_layer2_disjoint_json_keys_is_not_a_finding():
    p_body = json.dumps({"note": "secret"}).encode()
    q_body = json.dumps({"error": "not found"}).encode()
    verdict, _ = judge(p_status=200, p_body=p_body, q_status=200, q_body=q_body, p_canary_tokens=())
    assert verdict == OracleVerdict.NOT_A_FINDING


def test_layer2_much_smaller_html_body_is_not_a_finding():
    p_body = b"<html>" + b"x" * 1000 + b"</html>"
    q_body = b"<html>login</html>"
    verdict, _ = judge(p_status=200, p_body=p_body, q_status=200, q_body=q_body, p_canary_tokens=())
    assert verdict == OracleVerdict.NOT_A_FINDING


def test_layer3_canary_present_confirms():
    p_body = json.dumps({"note": "canary-4f8a2b"}).encode()
    q_body = json.dumps({"note": "canary-4f8a2b"}).encode()
    verdict, detail = judge(
        p_status=200,
        p_body=p_body,
        q_status=200,
        q_body=q_body,
        p_canary_tokens=("canary-4f8a2b",),
    )
    assert verdict == OracleVerdict.CONFIRMED_BY_CANARY
    assert "canary" in detail.lower()


def test_layer4_ambiguous_when_no_canary_and_not_clearly_different():
    p_body = json.dumps({"note": "some shared static content"}).encode()
    q_body = json.dumps({"note": "some shared static content"}).encode()
    verdict, _ = judge(p_status=200, p_body=p_body, q_status=200, q_body=q_body, p_canary_tokens=())
    assert verdict == OracleVerdict.AMBIGUOUS


def test_non_json_similar_sized_html_without_canary_is_ambiguous():
    p_body = b"<html>dashboard content here</html>"
    q_body = b"<html>dashboard content also here</html>"
    verdict, _ = judge(p_status=200, p_body=p_body, q_status=200, q_body=q_body, p_canary_tokens=())
    assert verdict == OracleVerdict.AMBIGUOUS

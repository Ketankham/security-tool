"""The layered access oracle (docs/03-check-catalogue.md §4.4) — the
mechanism that keeps authorization findings' false-positive rate near zero
by escalating through cheap-to-expensive layers and stopping at the first
confident answer.

Layers 1-3 are implemented here, purely deterministic. Layer 4 (an LLM
adjudicating the genuinely ambiguous middle: different status but partial
data, or no canary reachable) is not implemented yet — see the module
docstring in ``models.py``. Layer 5 (mandatory re-verification of *any*
positive verdict, canary included, before it can be labelled ``confirmed``)
lives in ``sentinel_checks.verification``, not here: this module only ever
proposes.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from .models import OracleVerdict

_NOT_A_FINDING_STATUSES = frozenset({401, 403, 404})

# Layer 2's "clearly different" heuristic for non-JSON (HTML) bodies: a
# denied persona's page more than this much smaller than the requester's is
# treated as a different page (a login wall, an empty state), not a leak.
# Deliberately conservative — false negatives here just fall through to
# Layer 3/4 rather than being wrongly cleared, whereas a false "clearly
# different" would suppress a real finding outright.
_STRUCTURAL_SIZE_RATIO_FLOOR = 0.3


def judge(
    *,
    p_status: int,
    p_body: bytes,
    q_status: int,
    q_body: bytes,
    p_canary_tokens: Sequence[str],
) -> tuple[OracleVerdict, str]:
    # Layer 1 (status): cheap, catches most.
    if q_status in _NOT_A_FINDING_STATUSES:
        return OracleVerdict.NOT_A_FINDING, f"Denied persona received HTTP {q_status}."

    # Layer 2 (structure): is Q's body clearly a different shape than P's?
    structurally_different, structure_note = _structurally_different(p_body, q_body)
    if structurally_different:
        return OracleVerdict.NOT_A_FINDING, structure_note

    # Layer 3 (canary): the strongest deterministic signal, no AI needed.
    q_text = q_body.decode("utf-8", errors="replace")
    for token in p_canary_tokens:
        if token and token in q_text:
            return (
                OracleVerdict.CONFIRMED_BY_CANARY,
                "Requesting persona's canary token found in the denied persona's response.",
            )

    # Layer 4 would adjudicate here. Without it, an ambiguous diff is
    # reported as ambiguous, not guessed at.
    return (
        OracleVerdict.AMBIGUOUS,
        "Status and structure did not clear this response, but no canary token confirmed a "
        "leak either — Layer 4 (LLM semantic adjudication) is not implemented yet, so this is "
        "reported as ambiguous rather than a candidate finding.",
    )


def _structurally_different(p_body: bytes, q_body: bytes) -> tuple[bool, str]:
    p_json = _try_parse_json(p_body)
    q_json = _try_parse_json(q_body)
    if p_json is not None and q_json is not None:
        if isinstance(p_json, dict) and isinstance(q_json, dict):
            p_keys, q_keys = set(p_json.keys()), set(q_json.keys())
            if p_keys and not (p_keys & q_keys):
                return True, "Denied persona's JSON response shares no keys with P's."
            if not q_json:
                return True, "Denied persona's JSON response is empty."
            return False, ""
        if isinstance(p_json, list) and isinstance(q_json, list):
            if p_json and not q_json:
                return True, "Denied persona's JSON response is an empty list."
            return False, ""
        return False, ""

    if not q_body:
        return True, "Denied persona's response body is empty."
    if p_body and len(q_body) < _STRUCTURAL_SIZE_RATIO_FLOOR * len(p_body):
        return True, "Denied persona's response is far smaller than P's (likely a different page)."
    return False, ""


def _try_parse_json(body: bytes) -> object | None:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

"""The re-proof gate's own invariants (docs/02 Phase 9, ADR-0001):
all-must-reproduce, early-out on first miss, and the >=2 floor."""

from __future__ import annotations

import pytest
from sentinel_verifier import ReproductionAttempt, Verifier


def _always(reproduced: bool):
    async def _reproduce(i: int) -> ReproductionAttempt:
        return ReproductionAttempt(reproduced=reproduced, detail=f"attempt {i}")

    return _reproduce


async def test_passes_when_all_attempts_reproduce():
    outcome = await Verifier().verify(_always(True))
    assert outcome.passed
    assert outcome.attempted_count == 2
    assert outcome.reproduced_count == 2


async def test_fails_and_stops_early_on_first_miss():
    outcome = await Verifier().verify(_always(False))
    assert not outcome.passed
    # Early-out: the first miss already fails the bar, so only one attempt runs.
    assert outcome.attempted_count == 1
    assert outcome.reproduced_count == 0


async def test_one_of_two_is_not_confirmed():
    calls = {"n": 0}

    async def flaky(i: int) -> ReproductionAttempt:
        calls["n"] += 1
        # Reproduces the first time, not the second — the classic flaky FP.
        return ReproductionAttempt(reproduced=(i == 0))

    outcome = await Verifier().verify(flaky)
    assert not outcome.passed
    assert outcome.reproduced_count == 1
    assert outcome.attempted_count == 2


async def test_can_require_more_than_two_reproductions():
    outcome = await Verifier(min_reproductions=3).verify(_always(True), attempts=3)
    assert outcome.passed
    assert outcome.reproduced_count == 3


async def test_attempts_below_min_is_rejected():
    with pytest.raises(ValueError):
        await Verifier(min_reproductions=2).verify(_always(True), attempts=1)


async def test_min_reproductions_floor():
    with pytest.raises(ValueError):
        Verifier(min_reproductions=0)


async def test_details_are_serialisable():
    outcome = await Verifier().verify(_always(True))
    d = outcome.details
    assert d["passed"] is True
    assert d["reproduced_count"] == 2
    assert len(d["attempts"]) == 2
    assert d["attempts"][0]["detail"] == "attempt 0"

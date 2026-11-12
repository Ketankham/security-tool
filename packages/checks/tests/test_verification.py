from sentinel_checks.verification import MIN_REPRODUCTIONS_FOR_CONFIRMED, verify_candidate


async def test_always_reproduces_passes():
    outcome = await verify_candidate(lambda: _const(True))
    assert outcome.attempted_count == MIN_REPRODUCTIONS_FOR_CONFIRMED
    assert outcome.reproduced_count == MIN_REPRODUCTIONS_FOR_CONFIRMED
    assert outcome.passed is True


async def test_never_reproduces_fails():
    outcome = await verify_candidate(lambda: _const(False))
    assert outcome.reproduced_count == 0
    assert outcome.passed is False


async def test_flaky_reproduction_is_counted_not_short_circuited():
    calls = {"n": 0}

    async def flaky() -> bool:
        calls["n"] += 1
        return calls["n"] % 2 == 1  # True, False, True, ...

    outcome = await verify_candidate(flaky, attempts=4)
    assert outcome.attempted_count == 4
    assert outcome.reproduced_count == 2
    assert outcome.passed is True  # 2 >= MIN_REPRODUCTIONS_FOR_CONFIRMED


async def test_below_threshold_does_not_pass():
    calls = {"n": 0}

    async def mostly_fails() -> bool:
        calls["n"] += 1
        return calls["n"] == 1  # only the first attempt reproduces

    outcome = await verify_candidate(mostly_fails, attempts=3)
    assert outcome.reproduced_count == 1
    assert outcome.passed is False


async def _const(value: bool) -> bool:
    return value

import pytest
from sentinel_core.state_machine import (
    InvalidResume,
    InvalidTransition,
    ScanState,
    ScanStateMachine,
)


def test_happy_path_linear_flow():
    m = ScanStateMachine()
    order = [
        ScanState.SCOPE_VERIFYING,
        ScanState.RECON,
        ScanState.AUTH_ESTABLISHING,
        ScanState.CRAWLING,
        ScanState.SURFACE_MAPPING,
        ScanState.PASSIVE_CHECKS,
        ScanState.TESTING,
        ScanState.VERIFYING,
        ScanState.TRIAGING,
        ScanState.REPORTING,
        ScanState.COMPLETE,
    ]
    for target in order:
        m.transition(target)
    assert m.current is ScanState.COMPLETE
    assert m.is_terminal


def test_unverified_scope_blocks():
    m = ScanStateMachine()
    m.transition(ScanState.SCOPE_VERIFYING)
    m.transition(ScanState.BLOCKED_UNVERIFIED)
    assert m.is_terminal
    with pytest.raises(InvalidTransition):
        m.transition(ScanState.RECON)


def test_auth_can_fail_hard():
    m = ScanStateMachine()
    m.transition(ScanState.SCOPE_VERIFYING)
    m.transition(ScanState.RECON)
    m.transition(ScanState.AUTH_ESTABLISHING)
    m.transition(ScanState.FAILED_AUTH)
    assert m.is_terminal


def test_invalid_skip_ahead_rejected():
    m = ScanStateMachine()
    with pytest.raises(InvalidTransition):
        m.transition(ScanState.TESTING)


def test_pause_and_resume_returns_to_prior_state():
    m = ScanStateMachine()
    m.transition(ScanState.SCOPE_VERIFYING)
    m.transition(ScanState.RECON)
    m.transition(ScanState.PAUSED)
    assert m.current is ScanState.PAUSED
    assert m.paused_from is ScanState.RECON

    resumed = m.resume()
    assert resumed is ScanState.RECON
    assert m.paused_from is None
    # and the scan can keep going from where it left off
    m.transition(ScanState.AUTH_ESTABLISHING)
    assert m.current is ScanState.AUTH_ESTABLISHING


def test_cannot_resume_a_scan_that_is_not_paused():
    m = ScanStateMachine()
    with pytest.raises(InvalidResume):
        m.resume()


def test_cancel_from_any_non_terminal_state():
    m = ScanStateMachine()
    m.transition(ScanState.SCOPE_VERIFYING)
    m.transition(ScanState.RECON)
    m.transition(ScanState.CANCELLED)
    assert m.is_terminal


def test_fail_records_reason():
    m = ScanStateMachine()
    m.transition(ScanState.SCOPE_VERIFYING)
    m.transition(ScanState.FAILED, reason="recon worker crashed 3 times")
    assert m.is_terminal
    assert m.fail_reason == "recon worker crashed 3 times"


def test_terminal_states_reject_all_transitions():
    m = ScanStateMachine()
    m.transition(ScanState.SCOPE_VERIFYING)
    m.transition(ScanState.CANCELLED)
    with pytest.raises(InvalidTransition):
        m.transition(ScanState.RECON)
    with pytest.raises(InvalidTransition):
        m.transition(ScanState.PAUSED)

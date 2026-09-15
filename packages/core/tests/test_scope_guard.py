from sentinel_core.scope_guard import DestructiveActionGuard, ScopeGuard, ScopeRule, ScopeVerdict


def make_guard(**kwargs):
    defaults = dict(allowed_hosts={"app.acme.test"}, target_ownership_verified=True)
    defaults.update(kwargs)
    return ScopeGuard(**defaults)


def test_blocks_unverified_target():
    guard = make_guard(target_ownership_verified=False)
    decision = guard.evaluate(method="GET", url="https://app.acme.test/")
    assert not decision.allowed
    assert decision.verdict is ScopeVerdict.BLOCKED_UNVERIFIED_TARGET


def test_allows_in_scope_host():
    guard = make_guard()
    decision = guard.evaluate(method="GET", url="https://app.acme.test/dashboard")
    assert decision.allowed


def test_blocks_out_of_scope_host():
    guard = make_guard()
    decision = guard.evaluate(method="GET", url="https://evil.example/")
    assert not decision.allowed
    assert decision.verdict is ScopeVerdict.BLOCKED_HOST


def test_wildcard_host_matches_subdomain():
    guard = make_guard(allowed_hosts={"*.acme.test"})
    decision = guard.evaluate(method="GET", url="https://api.acme.test/v1/users")
    assert decision.allowed


def test_wildcard_host_does_not_match_bare_domain_as_itself():
    # *.acme.test should not match "acme.test" exactly under our convention;
    # callers wanting both add both entries explicitly.
    guard = make_guard(allowed_hosts={"*.acme.test"})
    decision = guard.evaluate(method="GET", url="https://acme.test/")
    assert not decision.allowed


def test_exclude_path_rule_wins():
    guard = make_guard(
        rules=[ScopeRule(kind="path_prefix", pattern="/billing", effect="exclude", label="billing")]
    )
    decision = guard.evaluate(method="GET", url="https://app.acme.test/billing/invoices")
    assert not decision.allowed
    assert decision.verdict is ScopeVerdict.BLOCKED_PATH_EXCLUDED


def test_include_rules_switch_to_allowlist_mode():
    guard = make_guard(
        rules=[ScopeRule(kind="path_prefix", pattern="/app", effect="include", label="app-only")]
    )
    in_scope = guard.evaluate(method="GET", url="https://app.acme.test/app/settings")
    out_of_scope = guard.evaluate(method="GET", url="https://app.acme.test/marketing")
    assert in_scope.allowed
    assert not out_of_scope.allowed
    assert out_of_scope.verdict is ScopeVerdict.BLOCKED_PATH_NOT_INCLUDED


def test_method_exclude_rule():
    guard = make_guard(rules=[ScopeRule(kind="method", pattern="DELETE", effect="exclude")])
    decision = guard.evaluate(method="DELETE", url="https://app.acme.test/api/users/1")
    assert not decision.allowed
    assert decision.verdict is ScopeVerdict.BLOCKED_METHOD


def test_destructive_guard_flags_delete_url():
    guard = DestructiveActionGuard()
    check = guard.check(method="GET", url="https://app.acme.test/account/delete")
    assert check.is_suspect


def test_destructive_guard_flags_link_text():
    guard = DestructiveActionGuard()
    check = guard.check(
        method="GET", url="https://app.acme.test/x/42", link_text="Deactivate this user"
    )
    assert check.is_suspect


def test_destructive_guard_flags_non_idempotent_by_default():
    guard = DestructiveActionGuard(read_write_enabled=False)
    check = guard.check(method="POST", url="https://app.acme.test/api/comments")
    assert check.is_suspect


def test_destructive_guard_allows_non_idempotent_when_read_write_enabled():
    guard = DestructiveActionGuard(read_write_enabled=True)
    check = guard.check(method="POST", url="https://app.acme.test/api/comments")
    assert not check.is_suspect


def test_destructive_guard_allows_safe_get():
    guard = DestructiveActionGuard()
    check = guard.check(method="GET", url="https://app.acme.test/dashboard")
    assert not check.is_suspect

from datetime import UTC, datetime

from sentinel_reporter import ReportAsset, ReportEndpoint, ReportFinding, ScanReport


def _make_report(**overrides) -> ScanReport:
    defaults = dict(
        scan_id="scan-1",
        target_root_domain="acme.test",
        target_display_name="Acme",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        personas_crawled=["anonymous"],
        assets=[],
        endpoints=[],
        findings=[],
        is_degraded=False,
        degraded_reasons=[],
    )
    defaults.update(overrides)
    return ScanReport(**defaults)


def test_summary_counts_assets_endpoints_and_findings_by_confidence():
    report = _make_report(
        assets=[ReportAsset(host="acme.test", discovery_source="root_domain")],
        endpoints=[
            ReportEndpoint(method="GET", path_template="/", discovery_source="link"),
            ReportEndpoint(method="GET", path_template="/notes/{id}", discovery_source="link"),
        ],
        findings=[
            ReportFinding(
                rule_id="authz.horizontal", title="x", severity="high", confidence="confirmed"
            ),
            ReportFinding(
                rule_id="authz.vertical", title="y", severity="high", confidence="probable"
            ),
        ],
        personas_crawled=["anonymous", "member-a"],
    )
    assert report.summary == {
        "assets_found": 1,
        "endpoints_found": 2,
        "personas_crawled": 2,
        "findings_confirmed": 1,
        "findings_probable": 1,
    }


def test_to_dict_is_json_shaped_and_notes_authz_ran_when_more_than_anonymous_crawled():
    report = _make_report(personas_crawled=["anonymous", "member-a"])
    body = report.to_dict()
    assert body["scan_id"] == "scan-1"
    assert body["target"] == {"root_domain": "acme.test", "display_name": "Acme"}
    assert body["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert "authorization engine" in body["scope_note"]


def test_to_dict_scope_note_omits_authz_for_anonymous_only_crawl():
    report = _make_report(personas_crawled=["anonymous"])
    assert "authorization engine" not in report.to_dict()["scope_note"]


def test_to_dict_includes_degraded_reasons_verbatim():
    report = _make_report(is_degraded=True, degraded_reasons=["recon tool X unavailable"])
    body = report.to_dict()
    assert body["is_degraded"] is True
    assert body["degraded_reasons"] == ["recon tool X unavailable"]

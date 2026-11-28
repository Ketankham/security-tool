from datetime import UTC, datetime

from sentinel_reporter import (
    ReportAsset,
    ReportAuthorisation,
    ReportEndpoint,
    ReportFinding,
    ReportPath,
    ReportPort,
    ScanReport,
)


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


def test_scope_note_names_the_checks_that_ran_and_the_ones_that_did_not():
    report = _make_report(personas_crawled=["anonymous", "member-a"])
    report = type(report)(
        **{
            **{f: getattr(report, f) for f in report.__dataclass_fields__},
            "checks_run": ["security headers, cookies, CORS, exposed files and TLS"],
            "checks_skipped": ["injection testing", "session management"],
        }
    )
    body = report.to_dict()
    assert body["checks_run"] == ["security headers, cookies, CORS, exposed files and TLS"]
    assert body["checks_skipped"] == ["injection testing", "session management"]
    assert "then: security headers, cookies, CORS, exposed files and TLS." in body["scope_note"]
    assert "Not run: injection testing, session management." in body["scope_note"]
    assert "did not run, not that the target is clean" in body["scope_note"]


# --- Directory brute force and the authorisation behind it ---------------------


def _path(**overrides):
    values = dict(
        origin="https://acme.test",
        path="/.env",
        url="https://acme.test/.env",
        method="GET",
        status_code=200,
        category="config",
        verdict="confirmed",
        wordlist="sentinel-core",
        rule_id="exposed.env_file",
    )
    values.update(overrides)
    return ReportPath(**values)


def test_an_old_style_report_has_no_paths_and_an_unchanged_summary():
    body = _make_report().to_dict()
    assert body["paths"] == []
    assert body["authorisation"] is None
    assert set(body["summary"]) == {
        "assets_found",
        "endpoints_found",
        "personas_crawled",
        "findings_confirmed",
        "findings_probable",
    }


def test_paths_are_listed_and_counted_in_the_summary():
    report = _make_report(
        paths=[_path(), _path(path="/admin/", verdict="found", category="admin", rule_id=None)]
    )
    body = report.to_dict()
    assert body["summary"]["paths_found"] == 2
    assert body["summary"]["paths_confirmed"] == 1
    assert [p["path"] for p in body["paths"]] == ["/.env", "/admin/"]
    first = body["paths"][0]
    assert first["verdict"] == "confirmed" and first["rule_id"] == "exposed.env_file"
    # names, status, size and type only: there is nowhere for file content to go
    assert not {"body", "content", "text"} & set(first)


def test_the_authorisation_is_part_of_the_report():
    auth = ReportAuthorisation(
        username="alice",
        accepted_at=datetime(2026, 11, 25, 9, 30, tzinfo=UTC),
        client_name="Acme Ltd",
        tools=["dir_bruteforce"],
        statement_version="1",
        statement_text="I confirm Acme Ltd has authorised ...",
        target_environment="production",
    )
    body = _make_report(authorisation=auth).to_dict()
    assert body["authorisation"] == {
        "username": "alice",
        "accepted_at": "2026-11-25T09:30:00+00:00",
        "client_name": "Acme Ltd",
        "tools": ["dir_bruteforce"],
        "statement_version": "1",
        "statement_text": "I confirm Acme Ltd has authorised ...",
        "target_environment": "production",
    }


def _port(**overrides) -> ReportPort:
    values = dict(
        ip="203.0.113.7",
        hosts=["acme.test"],
        port=443,
        state="open",
        confidence="detected",
        found_by="nmap",
        service="https",
        product="nginx",
        version="1.24.0",
    )
    values.update(overrides)
    return ReportPort(**values)


def test_a_report_without_ports_keeps_its_old_shape():
    body = _make_report().to_dict()
    assert body["ports"] == []
    for key in ("open_ports", "ips_with_open_ports", "ports_unverified"):
        assert key not in body["summary"]


def test_ports_are_listed_and_counted_in_the_summary():
    report = _make_report(
        ports=[
            _port(),
            _port(port=22, service="ssh", product=None, version=None, confidence="port_guess"),
            _port(ip="203.0.113.8", port=80, confidence="port_guess", found_by="naabu"),
            _port(port=8443, state="filtered"),
        ]
    )
    body = report.to_dict()
    assert body["summary"]["open_ports"] == 3
    assert body["summary"]["ips_with_open_ports"] == 2
    assert body["summary"]["ports_unverified"] == 2
    assert [(p["ip"], p["port"]) for p in body["ports"]][:2] == [
        ("203.0.113.7", 443),
        ("203.0.113.7", 22),
    ]
    first = body["ports"][0]
    assert first["product"] == "nginx" and first["confidence"] == "detected"
    assert set(first) == {
        "ip", "hosts", "port", "protocol", "state", "service", "product", "version",
        "confidence", "found_by", "cdn",
    }  # fmt: skip


def test_script_output_has_nowhere_to_go_in_a_report():
    body = _make_report(ports=[_port()]).to_dict()
    assert not {"scripts", "script", "output", "extra_info", "banner"} & set(body["ports"][0])

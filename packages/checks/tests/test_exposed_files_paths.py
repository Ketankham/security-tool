"""probe_for_path / build_candidate: how a path found by directory brute
forcing is mapped to an exposed-file probe, and turned into a candidate."""

import pytest
from sentinel_checks.passive.exposed_files import (
    PROBES,
    Probe,
    build_candidate,
    matches_baseline,
    probe_for_path,
)
from sentinel_core.http_engine import EngineResponse


def _resp(status=200, body=b"", headers=None, url="http://h.test/x"):
    return EngineResponse(
        status_code=status,
        headers=headers or {},
        body=body,
        elapsed_ms=1.0,
        transcript_id="t-1",
        url=url,
    )


def test_every_existing_probe_path_maps_to_itself():
    for probe in PROBES:
        assert probe_for_path(probe.path) is probe
        assert probe_for_path(probe.path.lstrip("/")) is probe


def test_the_existing_probe_list_is_unchanged():
    """probe_for_path was added by refactoring five probes into factories:
    the passive check must still probe exactly these paths with these methods."""
    assert [(p.path, p.method, p.withhold, p.rule_id) for p in PROBES] == [
        ("/.env", "GET", True, "exposed.env_file"),
        ("/.env.local", "GET", True, "exposed.env_file"),
        ("/.env.production", "GET", True, "exposed.env_file"),
        ("/.env.backup", "GET", True, "exposed.env_file"),
        ("/.git/HEAD", "GET", False, "exposed.git_repository"),
        ("/.git/config", "GET", True, "exposed.git_config"),
        ("/.DS_Store", "GET", False, "exposed.ds_store"),
        ("/.htpasswd", "GET", True, "exposed.htpasswd"),
        ("/wp-config.php.bak", "GET", True, "exposed.config_backup"),
        ("/wp-config.php.old", "GET", True, "exposed.config_backup"),
        ("/phpinfo.php", "GET", False, "exposed.phpinfo"),
        ("/info.php", "GET", False, "exposed.phpinfo"),
        ("/server-status", "GET", False, "exposed.server_status"),
        ("/actuator/env", "GET", True, "exposed.actuator_env"),
        ("/openapi.json", "GET", False, "exposed.api_docs"),
        ("/swagger.json", "GET", False, "exposed.api_docs"),
        ("/v2/api-docs", "GET", False, "exposed.api_docs"),
        ("/backup.zip", "HEAD", False, "exposed.backup_file"),
        ("/site.zip", "HEAD", False, "exposed.backup_file"),
        ("/backup.sql", "HEAD", False, "exposed.backup_file"),
        ("/dump.sql", "HEAD", False, "exposed.backup_file"),
    ]


@pytest.mark.parametrize(
    ("path", "rule", "method", "withhold"),
    [
        (".env", "exposed.env_file", "GET", True),
        ("app/.env", "exposed.env_file", "GET", True),
        ("/config/.env.staging", "exposed.env_file", "GET", True),
        (".envrc", "exposed.env_file", "GET", True),
        ("sub/.git/HEAD", "exposed.git_repository", "GET", False),
        ("/old/.git/config", "exposed.git_config", "GET", True),
        ("x/.DS_Store", "exposed.ds_store", "GET", False),
        ("admin/.htpasswd", "exposed.htpasswd", "GET", True),
        ("wp-config.php.save", "exposed.config_backup", "GET", True),
        ("blog/wp-config.php.orig", "exposed.config_backup", "GET", True),
        ("site-2020.zip", "exposed.backup_file", "HEAD", False),
        ("Backups/DB.SQL.GZ", "exposed.backup_file", "HEAD", False),
        ("a.tar.gz", "exposed.backup_file", "HEAD", False),
        ("a.tgz", "exposed.backup_file", "HEAD", False),
        ("a.bz2", "exposed.backup_file", "HEAD", False),
        ("a.7z", "exposed.backup_file", "HEAD", False),
        ("a.rar", "exposed.backup_file", "HEAD", False),
        ("a.dump", "exposed.backup_file", "HEAD", False),
        ("data.db", "exposed.backup_file", "HEAD", False),
        ("data.sqlite", "exposed.backup_file", "HEAD", False),
        ("a.tar", "exposed.backup_file", "HEAD", False),
        ("a.gz", "exposed.backup_file", "HEAD", False),
        # An archive suffix wins: never GET something that may be a huge download.
        (".env.sql", "exposed.backup_file", "HEAD", False),
        ("wp-config.php.gz", "exposed.backup_file", "HEAD", False),
    ],
)
def test_path_families_map_to_the_right_probe(path, rule, method, withhold):
    probe = probe_for_path(path)
    assert isinstance(probe, Probe)
    assert probe.rule_id == rule
    assert probe.method == method
    assert probe.withhold is withhold
    assert probe.path == "/" + path.lstrip("/")


@pytest.mark.parametrize(
    "path",
    [
        "",
        "admin/",
        "admin",
        "login.php",
        "swagger-ui/",
        "foo.git/HEAD",  # not a .git directory
        "x/.DS_Store.txt",
        "wp-config.php",  # the bare file is PHP source, served as nothing
        "wp-config.php.",
        "robots.txt",
        "a/../.env",
        ".env?x=1",
        ".env #",
        "dir/zip",
    ],
)
def test_ordinary_paths_have_no_probe(path):
    assert probe_for_path(path) is None


def test_the_returned_probes_validate_what_they_claim():
    env = probe_for_path("deep/.env.old")
    assert env is not None
    assert env.validate(_resp(body=b"DB_USER=a\nDB_PASSWORD=zzzzzz\n")) is not None
    assert env.validate(_resp(body=b"<html><body>Not here</body></html>")) is None

    head = probe_for_path("x/.git/HEAD")
    assert head is not None
    assert head.validate(_resp(body=b"ref: refs/heads/main\n")) is not None
    assert head.validate(_resp(body=b"hello")) is None

    cfg = probe_for_path("x/.git/config")
    assert cfg is not None
    assert cfg.validate(_resp(body=b"[core]\n\trepositoryformatversion = 0\n")) is not None

    wp = probe_for_path("wp-config.php.swp")
    assert wp is not None
    assert wp.validate(_resp(body=b"define('DB_NAME','x'); define('DB_PASSWORD','y');")) is not None
    assert wp.validate(_resp(body=b"nothing")) is None

    archive = probe_for_path("old/site.tar.gz")
    assert archive is not None
    zip_headers = {"content-type": "application/gzip", "content-length": "52311"}
    assert archive.validate(_resp(headers=zip_headers)) is not None
    small = {"content-type": "application/gzip", "content-length": "20"}
    assert archive.validate(_resp(headers=small)) is None
    assert (
        archive.validate(_resp(headers={"content-type": "text/html", "content-length": "9999"}))
        is None
    )


def test_matches_baseline_rules():
    get = probe_for_path(".env")
    head = probe_for_path("a.zip")
    assert get is not None and head is not None
    assert matches_baseline(get, _resp(body=b"x"), _resp(body=b"x"))
    assert not matches_baseline(get, _resp(body=b"x"), _resp(body=b"y"))
    assert not matches_baseline(get, _resp(body=b"x"), None)
    assert not matches_baseline(get, _resp(body=b"x"), _resp(status=404, body=b"x"))
    html = {"content-type": "text/html"}
    assert matches_baseline(head, _resp(headers=html), _resp(headers=html))
    assert not matches_baseline(
        head, _resp(headers={"content-type": "application/zip"}), _resp(headers=html)
    )


async def test_build_candidate_reproduces_through_the_given_fetch():
    probe = probe_for_path("a/.env")
    assert probe is not None
    seen = []
    good = _resp(body=b"DB_HOST=db\nDB_PASSWORD=sekret-sekret\n")

    async def fetch(method, url, **kwargs):
        seen.append((method, url, kwargs))
        return good

    matched = probe.validate(good)
    assert matched is not None
    cand = build_candidate(probe, "http://h.test", "http://h.test/a/.env", good, matched, fetch)
    assert cand.rule_id == "exposed.env_file"
    assert cand.subject == "/a/.env"
    assert cand.origin == "http://h.test"
    assert cand.title.endswith("(h.test/a/.env)")
    assert "sekret" not in cand.narrative + cand.reproduction_curl + str(cand.evidence)
    assert "deliberately not stored" in cand.narrative
    assert cand.evidence[0].transcript_id == "t-1"
    assert cand.reproduce is not None
    assert await cand.reproduce() is True
    assert seen == [("GET", "http://h.test/a/.env", {"withhold_body": True})]

    async def gone(method, url, **kwargs):
        return _resp(status=404, body=b"nope")

    cand2 = build_candidate(probe, "http://h.test", "http://h.test/a/.env", good, matched, gone)
    assert cand2.reproduce is not None
    assert await cand2.reproduce() is False

    async def unreachable(method, url, **kwargs):
        return None

    cand3 = build_candidate(
        probe, "http://h.test", "http://h.test/a/.env", good, matched, unreachable
    )
    assert cand3.reproduce is not None
    assert await cand3.reproduce() is False

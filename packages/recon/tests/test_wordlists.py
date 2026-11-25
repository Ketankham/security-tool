"""Tests for the vendored wordlists and their loader (PR-B, directory brute force)."""

import dataclasses
import hashlib
import re
from collections import Counter
from importlib import resources

import pytest
from sentinel_checks.passive.exposed_files import PROBES
from sentinel_core.scan_options import WORDLIST_MAX_ENTRIES
from sentinel_core.scope_guard import DestructiveActionGuard
from sentinel_recon import wordlists
from sentinel_recon.wordlists import Entry, Wordlist, is_archive, load

CATEGORIES = {"config", "backup", "vcs", "admin", "api"}
GUARD = DestructiveActionGuard()

# Extra read-only screen on top of the guard: words that name an action which could
# change state when requested with GET.
STATE_CHANGING_WORDS = wordlists.STATE_CHANGING_WORDS


def _file_bytes(filename: str) -> bytes | None:
    ref = resources.files("sentinel_recon.wordlists").joinpath(filename)
    return ref.read_bytes() if ref.is_file() else None


CORE_BYTES = _file_bytes("sentinel-core.txt")
SECLISTS_BYTES = _file_bytes("seclists-common.txt")
needs_seclists = pytest.mark.skipif(
    SECLISTS_BYTES is None, reason="seclists-common.txt is not vendored"
)


@pytest.fixture(autouse=True)
def _fresh_cache():
    load.cache_clear()
    yield
    load.cache_clear()


def _core_rows() -> list[tuple[str, str]]:
    """(category, path) pairs read straight from the file, independent of the loader."""
    assert CORE_BYTES is not None
    rows = []
    for line in CORE_BYTES.decode("utf-8").split("\n"):
        if not line or line.startswith("#"):
            continue
        category, sep, path = line.partition("\t")
        assert sep == "\t", f"line without a tab: {line!r}"
        rows.append((category, path))
    return rows


def _rule_violations(path: str) -> list[str]:
    problems = []
    if path.startswith("/"):
        problems.append("leading slash")
    if not path.isascii():
        problems.append("non-ASCII")
    if re.search(r"\s", path) or any(ord(c) < 32 or ord(c) == 127 for c in path):
        problems.append("whitespace/control")
    for bad in ("#", "?", "%", ".."):
        if bad in path:
            problems.append(f"contains {bad}")
    if "FUZZ" in path:
        problems.append("contains FUZZ")
    if not path:
        problems.append("empty")
    if len(path) > 200:
        problems.append("too long")
    return problems


# --------------------------------------------------------------------- is_archive


@pytest.mark.parametrize(
    "path",
    [
        "backup.zip",
        "site.tar",
        "site.tar.gz",
        "site.tgz",
        "dump.gz",
        "dump.bz2",
        "files.7z",
        "files.rar",
        "db.sql",
        "db.sql.gz",
        "backup.dump",
        "data.db",
        "data.sqlite",
        "BACKUP.ZIP",
        "Site.Tar.Gz",
        "DB.SQL.GZ",
        "Thumbs.DB",
        "sub/dir/backup.zip",
    ],
)
def test_is_archive_true(path):
    assert is_archive(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "archive/",
        "archive",
        "backup/",
        "backup.zip/",
        "zip",
        ".env",
        "index.php.bak",
        "wp-config.php~",
        "db.sqlite3",
        "dbxsql",
        "tar.gz.txt",
        "backup.zipx",
        "config.json",
        "",
    ],
)
def test_is_archive_false(path):
    assert is_archive(path) is False


def test_is_archive_distinguishes_tar_gz_from_gz_and_sql_gz_from_gz():
    assert is_archive("x.tar.gz") and is_archive("x.gz")
    assert is_archive("x.sql.gz") and is_archive("x.sql")
    assert not is_archive("x.tar.gz.bak")


# ----------------------------------------------------------------------- loader


def test_dataclasses_are_frozen_and_slotted():
    entry = Entry("config", ".env")
    wl = Wordlist("n", "0" * 64, [entry])
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.path = "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        wl.name = "x"
    assert not hasattr(entry, "__dict__")
    assert not hasattr(wl, "__dict__")


def test_parse_core_ignores_comments_and_blank_lines():
    text = "# header\n\nconfig\t.env\n   \n#config\tskipped\nadmin\tadmin/\n"
    entries, rejected = wordlists._parse("sentinel-core", text)
    assert entries == [Entry("config", ".env"), Entry("admin", "admin/")]
    assert rejected == []


def test_parse_strips_trailing_carriage_return():
    entries, rejected = wordlists._parse("sentinel-core", "# c\r\nconfig\t.env\r\napi\tapi/v1/\r\n")
    assert entries == [Entry("config", ".env"), Entry("api", "api/v1/")]
    assert rejected == []
    entries, rejected = wordlists._parse("seclists-common", ".bashrc\r\n\r\nadmin\r\n")
    assert [e.path for e in entries] == [".bashrc", "admin"]
    assert rejected == []


@pytest.mark.parametrize(
    "line",
    [
        ".env",  # no tab
        "config .env",  # space instead of tab
        "bogus\t.env",  # unknown category
        "config\t",  # empty path
        "config\t/leading",
        "config\twith space",
        "config\thas#hash",
        "config\thas?query",
        "config\tpercent%20",
        "config\ta/../b",
        "config\tFUZZ",
        "config\ta\tb",  # extra tab means whitespace in the path
        "config\tcafé",
        "config\t" + "a" * 201,
    ],
)
def test_parse_core_rejects_malformed_lines_without_crashing(line):
    entries, rejected = wordlists._parse("sentinel-core", f"admin\tadmin/\n{line}\napi\tapi/\n")
    assert [e.path for e in entries] == ["admin/", "api/"]
    assert rejected == [line]


def test_parse_rejects_duplicates_keeping_the_first():
    entries, rejected = wordlists._parse("sentinel-core", "config\t.env\nbackup\t.env\n")
    assert entries == [Entry("config", ".env")]
    assert rejected == ["backup\t.env"]


def test_parse_seclists_gives_every_entry_category_common():
    entries, rejected = wordlists._parse(
        "seclists-common", "# note\nadmin\n.git/HEAD\nbad path\n/abs\n"
    )
    assert entries == [Entry("common", "admin"), Entry("common", ".git/HEAD")]
    assert rejected == ["bad path", "/abs"]


def test_unknown_name_returns_none():
    assert load("nope") is None
    assert load("") is None
    assert load("SENTINEL-CORE") is None


def test_missing_file_returns_none(monkeypatch):
    monkeypatch.setitem(wordlists._FILES, "sentinel-core", "does-not-exist.txt")
    assert load("sentinel-core") is None


def test_load_with_fake_file_computes_sha256_and_entries(monkeypatch):
    data = b"# c\r\nconfig\t.env\r\nbackup\tbackup.zip\r\nbroken line\r\n"
    monkeypatch.setattr(wordlists, "_read_bytes", lambda filename: data)
    wl = load("sentinel-core")
    assert wl is not None
    assert wl.name == "sentinel-core"
    assert wl.sha256 == hashlib.sha256(data).hexdigest()
    assert wl.entries == [Entry("config", ".env"), Entry("backup", "backup.zip")]


def test_load_is_cached_and_returns_the_same_object():
    first = load("sentinel-core")
    assert first is not None
    assert load("sentinel-core") is first
    load.cache_clear()
    assert load("sentinel-core") is not first


def test_load_undecodable_bytes_do_not_crash(monkeypatch):
    monkeypatch.setattr(
        wordlists, "_read_bytes", lambda filename: b"config\t.env\nconfig\t\xff\xfe\n"
    )
    wl = load("sentinel-core")
    assert wl is not None
    assert [e.path for e in wl.entries] == [".env"]


# ----------------------------------------------------------- shipped sentinel-core


def test_sentinel_core_is_shipped_and_loads():
    assert CORE_BYTES is not None
    wl = load("sentinel-core")
    assert wl is not None
    assert wl.name == "sentinel-core"
    assert wl.sha256 == hashlib.sha256(CORE_BYTES).hexdigest()
    assert len(wl.sha256) == 64


def test_sentinel_core_has_no_malformed_lines():
    raw = wordlists._load_raw("sentinel-core")
    assert raw is not None
    data, entries, rejected = raw
    assert rejected == []
    assert len(entries) == len(_core_rows())


def test_sentinel_core_file_format_is_clean():
    assert CORE_BYTES is not None
    assert b"\r" not in CORE_BYTES
    assert CORE_BYTES.isascii()
    assert CORE_BYTES.startswith(b"# ")
    for line in CORE_BYTES.decode("ascii").split("\n"):
        if not line or line.startswith("#"):
            continue
        assert line == line.strip("\n")
        assert line.count("\t") == 1, line


def test_sentinel_core_loader_matches_the_file():
    wl = load("sentinel-core")
    assert wl is not None
    assert [(e.category, e.path) for e in wl.entries] == _core_rows()


def test_sentinel_core_size_within_limits():
    wl = load("sentinel-core")
    assert wl is not None
    assert 1000 <= len(wl.entries) <= WORDLIST_MAX_ENTRIES["sentinel-core"]


def test_sentinel_core_categories_and_bands():
    wl = load("sentinel-core")
    assert wl is not None
    counts = Counter(e.category for e in wl.entries)
    assert set(counts) <= CATEGORIES
    assert counts["vcs"] >= 40
    assert counts["admin"] >= 200
    assert counts["api"] >= 200
    assert counts["config"] >= 150
    assert counts["backup"] >= 150
    assert set(counts) == CATEGORIES


def test_sentinel_core_entries_obey_the_entry_rules():
    problems = {path: _rule_violations(path) for _, path in _core_rows() if _rule_violations(path)}
    assert problems == {}


def test_sentinel_core_entries_are_unique():
    paths = [path for _, path in _core_rows()]
    dupes = [p for p, n in Counter(paths).items() if n > 1]
    assert dupes == []


def test_sentinel_core_has_no_case_only_duplicates_of_archives():
    # Case-sensitive uniqueness is the rule, but two archives that differ only by
    # case would be a copy/paste slip, so keep those out too.
    archives = [path.lower() for _, path in _core_rows() if is_archive(path)]
    assert len(archives) == len(set(archives))


def test_sentinel_core_covers_every_exposed_file_probe():
    paths = {path for _, path in _core_rows()}
    missing = [probe.path for probe in PROBES if probe.path.lstrip("/") not in paths]
    assert missing == []


def test_sentinel_core_archives_are_all_category_backup():
    archives = [(c, p) for c, p in _core_rows() if is_archive(p)]
    assert len(archives) >= 60
    assert [(c, p) for c, p in archives if c != "backup"] == []


def test_sentinel_core_has_a_useful_number_of_archives_and_dumps():
    archives = [p for _, p in _core_rows() if is_archive(p)]
    assert 60 <= len(archives) <= 200
    assert {"backup.zip", "site.zip", "backup.sql", "dump.sql", "db.sql.gz"} <= set(archives)


def test_sentinel_core_has_no_state_changing_entries_under_the_guard():
    flagged = [
        (path, GUARD.check(method="GET", url=f"https://example.test/{path}").matched_pattern)
        for _, path in _core_rows()
        if GUARD.check(method="GET", url=f"https://example.test/{path}").is_suspect
    ]
    assert flagged == []


def test_sentinel_core_has_no_state_changing_words():
    flagged = [
        path
        for _, path in _core_rows()
        if set(re.findall(r"[a-z0-9]+", path.lower())) & STATE_CHANGING_WORDS
    ]
    assert flagged == []


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.local",
        ".git/HEAD",
        ".svn/entries",
        ".DS_Store",
        "wp-config.php.bak",
        "phpinfo.php",
        "admin/",
        "administrator/",
        "wp-admin",
        "wp-login.php",
        "phpmyadmin/",
        "adminer.php",
        "manager/html",
        "jenkins/",
        "grafana/",
        "kibana/",
        "solr/",
        "api/",
        "api/v1/",
        "v1/",
        "swagger-ui/",
        "graphql",
        "actuator/health",
        "healthz",
        "robots.txt",
        "sitemap.xml",
        ".well-known/security.txt",
        "web.config",
        "docker-compose.yml",
        "composer.json",
        "package.json",
    ],
)
def test_sentinel_core_contains_the_obvious_entries(path):
    assert path in {p for _, p in _core_rows()}


def test_sentinel_core_categories_match_the_kind_of_entry():
    rows = dict((p, c) for c, p in _core_rows())
    assert rows[".git/HEAD"] == "vcs"
    assert rows[".git/config"] == "vcs"
    assert rows[".env"] == "config"
    assert rows["backup.zip"] == "backup"
    assert rows["wp-login.php"] == "admin"
    assert rows["openapi.json"] == "api"


# --------------------------------------------------------- shipped seclists-common


def test_seclists_absent_means_load_returns_none():
    if SECLISTS_BYTES is not None:
        pytest.skip("seclists-common.txt is vendored")
    assert load("seclists-common") is None


@needs_seclists
def test_seclists_loads_with_category_common_and_correct_sha256():
    assert SECLISTS_BYTES is not None
    wl = load("seclists-common")
    assert wl is not None
    assert wl.name == "seclists-common"
    assert wl.sha256 == hashlib.sha256(SECLISTS_BYTES).hexdigest()
    assert {e.category for e in wl.entries} == {"common"}


@needs_seclists
def test_seclists_has_no_malformed_lines_and_fits_the_ceiling():
    raw = wordlists._load_raw("seclists-common")
    assert raw is not None
    _data, entries, rejected = raw
    assert rejected == []
    assert 1000 <= len(entries) <= WORDLIST_MAX_ENTRIES["seclists-common"]


@needs_seclists
def test_seclists_file_is_one_clean_path_per_line():
    assert SECLISTS_BYTES is not None
    assert SECLISTS_BYTES.isascii()
    assert b"\r" not in SECLISTS_BYTES
    assert SECLISTS_BYTES.endswith(b"\n")
    lines = SECLISTS_BYTES.decode("ascii").split("\n")[:-1]
    assert all(line and not line.startswith("#") for line in lines)
    assert len(lines) == len(set(lines))
    assert {line: _rule_violations(line) for line in lines if _rule_violations(line)} == {}


@needs_seclists
def test_seclists_has_nothing_the_destructive_guard_flags():
    wl = load("seclists-common")
    assert wl is not None
    flagged = [
        e.path
        for e in wl.entries
        if GUARD.check(method="GET", url=f"https://example.test/{e.path}").is_suspect
    ]
    assert flagged == []


@needs_seclists
def test_seclists_ships_licence_and_provenance_readme():
    licence = _file_bytes("SECLISTS-LICENSE")
    readme = _file_bytes("README.md")
    assert licence is not None and b"MIT License" in licence and b"Daniel Miessler" in licence
    assert readme is not None
    text = readme.decode("utf-8")
    assert "raw.githubusercontent.com/danielmiessler/SecLists/" in text
    assert "Discovery/Web-Content/common.txt" in text
    assert SECLISTS_BYTES is not None
    assert hashlib.sha256(SECLISTS_BYTES).hexdigest() in text


def test_readme_exists():
    readme = _file_bytes("README.md")
    assert readme is not None
    if SECLISTS_BYTES is None:
        assert b"seclists-common" in readme


def test_loader_never_returns_state_changing_entries_from_any_list():
    for name in ("sentinel-core", "seclists-common"):
        wl = load(name)
        if wl is None:
            continue
        assert not [e.path for e in wl.entries if wordlists.looks_state_changing(e.path)]


@needs_seclists
def test_seclists_state_changing_names_are_screened_out_at_load():
    wl = load("seclists-common")
    assert wl is not None
    paths = {e.path for e in wl.entries}
    for risky in ("install", "setup", "upload", "cron", "register", "forgot-password", "checkout"):
        assert risky not in paths
    assert "admin" in paths and "login" in paths  # reading these is fine
    assert wl.skipped_state_changing > 20
    assert len(wl.entries) + wl.skipped_state_changing <= WORDLIST_MAX_ENTRIES["seclists-common"]


def test_curated_list_loses_nothing_to_the_screen():
    wl = load("sentinel-core")
    assert wl is not None
    assert wl.skipped_state_changing == 0


def test_looks_state_changing_matches_words_not_substrings():
    assert wordlists.looks_state_changing("admin/delete-user")
    assert wordlists.looks_state_changing("Setup.php")
    assert not wordlists.looks_state_changing("installation-guide.html")
    assert not wordlists.looks_state_changing("settings")
    assert not wordlists.looks_state_changing("payments-docs")

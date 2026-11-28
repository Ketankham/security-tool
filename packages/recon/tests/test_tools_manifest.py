"""The CI tools-manifest gate (infra/scripts/tools_manifest_check.py)."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    "tools_manifest_check", ROOT / "infra/scripts/tools_manifest_check.py"
)
assert _spec and _spec.loader
tmc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tmc)

DOCKERFILE = """RUN go install github.com/x/subfinder/v2/cmd/subfinder@v2.17.0 \\
    && go install github.com/x/httpx/cmd/httpx@v1.6.10 \\
    && mv /out/httpx /out/pd-httpx"""


def _manifest(**overrides):
    tools = [
        {"name": "subfinder", "module": "github.com/x/subfinder/v2/cmd/subfinder",
         "version": "v2.17.0", "licence": "MIT", "source": "s", "used_for": "u"},
        {"name": "httpx", "module": "github.com/x/httpx/cmd/httpx",
         "version": "v1.6.10", "licence": "MIT", "source": "s", "used_for": "u"},
    ]  # fmt: skip
    for t in tools:
        t.update(overrides.get(t["name"], {}))
    return {"permitted_licences": ["MIT", "Apache-2.0"], "tools": tools}


def test_real_repo_manifest_matches_dockerfile():
    problems = tmc.check(
        (ROOT / "infra/docker/Dockerfile.worker").read_text(),
        json.loads((ROOT / "infra/tools-manifest.json").read_text()),
    )
    assert problems == []


def test_passes_when_in_sync():
    assert tmc.check(DOCKERFILE, _manifest()) == []


def test_flags_version_drift_unlisted_tool_and_copyleft():
    extra = DOCKERFILE + "\nRUN go install github.com/y/nmapish/cmd/nmapish@v1.0.0"
    problems = tmc.check(extra, _manifest(httpx={"version": "v1.6.9", "licence": "AGPL-3.0"}))
    text = "\n".join(problems)
    assert "nmapish@v1.0.0 is installed but not in the tools manifest" in text
    assert "installs v1.6.10, manifest says v1.6.9" in text
    assert "licence 'AGPL-3.0' is not permitted" in text


def test_flags_stale_manifest_entry():
    only_subfinder = "RUN go install github.com/x/subfinder/v2/cmd/subfinder@v2.17.0"
    problems = tmc.check(only_subfinder, _manifest())
    assert any("in the manifest but not installed" in p for p in problems)


def test_root_module_install_with_a_major_version_suffix_is_matched():
    """ffuf is installed from its root module path (…/ffuf/v2, no /cmd/…)."""
    dockerfile = "RUN go install github.com/ffuf/ffuf/v2@v2.3.0 \\\n    && /out/ffuf -V"
    assert tmc.installed_modules(dockerfile) == {"github.com/ffuf/ffuf/v2": "v2.3.0"}
    manifest = {
        "permitted_licences": ["MIT"],
        "tools": [
            {"name": "ffuf", "module": "github.com/ffuf/ffuf/v2", "version": "v2.3.0",
             "licence": "MIT", "source": "s", "used_for": "u"},
        ],
    }  # fmt: skip
    assert tmc.check(dockerfile, manifest) == []
    manifest["tools"][0]["version"] = "v2.2.0"
    assert any(
        "installs v2.3.0, manifest says v2.2.0" in p for p in tmc.check(dockerfile, manifest)
    )


APT_DOCKERFILE = (
    DOCKERFILE
    + """
RUN apt-get update && apt-get install -y --no-install-recommends \\
        curl ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends nmap=7.93+dfsg1-1 \\
    && rm -rf /var/lib/apt/lists/* \\
    && nmap --version
"""
)


def _apt_entry(**overrides):
    entry = {
        "name": "nmap", "kind": "apt", "package": "nmap", "version": "distro",
        "licence": "NPSL", "source": "https://nmap.org", "used_for": "u",
        "exception": "approved internal use", "approved_by": "Ketan",
        "approved_on": "2026-11-28",
    }  # fmt: skip
    entry.update(overrides)
    return entry


def _with_apt(entry):
    m = _manifest()
    m["tools"].append(entry)
    return m


def test_installed_apt_packages_strip_pins_and_stop_at_shell_operators():
    assert tmc.installed_apt_packages(APT_DOCKERFILE) == {"curl", "ca-certificates", "nmap"}
    assert tmc.installed_apt_packages("RUN apt-get install -y a=1.0 b:amd64 && echo notapkg") == {
        "a",
        "b",
    }
    assert tmc.installed_apt_packages(DOCKERFILE) == set()


def test_apt_entry_with_recorded_exception_passes():
    assert tmc.check(APT_DOCKERFILE, _with_apt(_apt_entry())) == []


def test_apt_entry_not_installed_is_stale():
    problems = tmc.check(DOCKERFILE, _with_apt(_apt_entry()))
    assert any("nmap (apt) is in the manifest but not installed" in p for p in problems)


def test_unpermitted_licence_without_exception_is_rejected():
    problems = tmc.check(APT_DOCKERFILE, _with_apt(_apt_entry(exception="")))
    assert any(
        "licence 'NPSL' is not permitted" in p and "no 'exception' note" in p for p in problems
    )


def test_exception_must_say_who_approved_it_and_when():
    problems = tmc.check(APT_DOCKERFILE, _with_apt(_apt_entry(approved_by="", approved_on="")))
    text = "\n".join(problems)
    assert "needs 'approved_by'" in text and "needs 'approved_on'" in text


def test_permitted_licence_needs_no_exception():
    entry = _apt_entry(licence="MIT", exception="", approved_by="", approved_on="")
    assert tmc.check(APT_DOCKERFILE, _with_apt(entry)) == []


def test_unknown_kind_and_missing_package_are_reported():
    problems = tmc.check(APT_DOCKERFILE, _with_apt(_apt_entry(kind="brew")))
    assert any("unknown kind 'brew'" in p for p in problems)
    broken = _apt_entry()
    del broken["package"]
    assert any("needs a 'package'" in p for p in tmc.check(APT_DOCKERFILE, _with_apt(broken)))


def test_go_tool_with_unpermitted_licence_still_needs_an_exception():
    problems = tmc.check(DOCKERFILE, _manifest(httpx={"licence": "AGPL-3.0"}))
    assert any("AGPL-3.0" in p and "no 'exception' note" in p for p in problems)


def test_real_manifest_records_the_nmap_exception_with_approver_and_date():
    manifest = json.loads((ROOT / "infra/tools-manifest.json").read_text())
    nmap = next(t for t in manifest["tools"] if t["name"] == "nmap")
    assert nmap["kind"] == "apt" and nmap["licence"] == "NPSL"
    assert nmap["approved_by"] and nmap["approved_on"] and "ADR-0002" in nmap["exception"]
    assert "nmap" in tmc.installed_apt_packages(
        (ROOT / "infra/docker/Dockerfile.worker").read_text()
    )

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

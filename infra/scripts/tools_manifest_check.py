#!/usr/bin/env python3
"""Keeps the worker's external tools honest (ADR-0002).

licence_check.py covers Python packages; this covers the binaries the worker
image installs: Go tools built with `go install` and system packages installed
with `apt-get install`. Fails when:

- a `go install module@version` in Dockerfile.worker is not in
  infra/tools-manifest.json, or the versions differ;
- a manifest entry is no longer installed (stale manifest): a Go entry is
  matched by its `module`, an `"kind": "apt"` entry by its `package`;
- a manifest entry has a licence outside `permitted_licences`, unless it
  carries a non-empty `exception` note together with `approved_by` and
  `approved_on` (so adding, say, an AGPL tool needs a deliberate, attributed
  manifest change; nothing slips in silently);
- an entry is missing a required field.

Plain system packages that are not listed in the manifest (curl,
ca-certificates, ...) are not checked: the manifest is for the scanning tools.

Usage: python infra/scripts/tools_manifest_check.py [dockerfile] [manifest]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GO_INSTALL = re.compile(r"go\s+install\s+(?P<module>[^\s@]+)@(?P<version>[^\s\\&;]+)")
# A backslash-newline continues the command; any other newline ends it.
APT_INSTALL = re.compile(r"apt-get\s+install\b(?P<args>(?:\\\n|[^\n])*)")
_COMMON_KEYS = ("name", "version", "licence", "source", "used_for")


def installed_modules(dockerfile_text: str) -> dict[str, str]:
    return {m["module"]: m["version"] for m in GO_INSTALL.finditer(dockerfile_text)}


def installed_apt_packages(dockerfile_text: str) -> set[str]:
    """Package names given to `apt-get install` (version pins and arch
    suffixes stripped). The package list ends at the first shell operator."""
    packages: set[str] = set()
    for match in APT_INSTALL.finditer(dockerfile_text):
        args = match["args"].replace("\\\n", " ")
        args = re.split(r"&&|\|\||;|\|", args, maxsplit=1)[0]
        for token in args.split():
            if token.startswith("-"):
                continue
            packages.add(re.split(r"[=:]", token, maxsplit=1)[0])
    return packages


def _entry_problems(label: str, entry: dict, permitted: set[str], extra_keys: tuple) -> list[str]:
    problems: list[str] = []
    for key in (*_COMMON_KEYS, *extra_keys):
        if not entry.get(key):
            problems.append(f"{label}: manifest entry is missing '{key}'.")
    if entry.get("licence") not in permitted:
        if not (entry.get("exception") or "").strip():
            problems.append(
                f"{entry.get('name', label)}: licence {entry.get('licence')!r} is not permitted "
                f"({', '.join(sorted(permitted))}) and the entry has no 'exception' note."
            )
        else:
            for key in ("approved_by", "approved_on"):
                if not entry.get(key):
                    problems.append(
                        f"{entry.get('name', label)}: an exception needs '{key}' "
                        "(who approved it, and when)."
                    )
    return problems


def check(dockerfile_text: str, manifest: dict) -> list[str]:
    problems: list[str] = []
    permitted = set(manifest.get("permitted_licences", []))
    tools = manifest.get("tools", [])
    go_listed = {t["module"]: t for t in tools if t.get("kind", "go") == "go" and "module" in t}
    apt_listed = {t["package"]: t for t in tools if t.get("kind") == "apt" and "package" in t}
    go_installed = installed_modules(dockerfile_text)
    apt_installed = installed_apt_packages(dockerfile_text)

    for t in tools:
        kind = t.get("kind", "go")
        if kind == "go" and "module" not in t:
            problems.append(f"{t.get('name', '?')}: a Go manifest entry needs a 'module'.")
        elif kind == "apt" and "package" not in t:
            problems.append(f"{t.get('name', '?')}: an apt manifest entry needs a 'package'.")
        elif kind not in ("go", "apt"):
            problems.append(f"{t.get('name', '?')}: unknown kind {kind!r} (use 'go' or 'apt').")

    for module, version in sorted(go_installed.items()):
        entry = go_listed.get(module)
        if entry is None:
            problems.append(f"{module}@{version} is installed but not in the tools manifest.")
            continue
        if entry.get("version") != version:
            problems.append(
                f"{module}: Dockerfile installs {version}, manifest says {entry.get('version')}."
            )
    for module, entry in sorted(go_listed.items()):
        if module not in go_installed:
            problems.append(f"{module} is in the manifest but not installed by the Dockerfile.")
        problems += _entry_problems(module, entry, permitted, ("module",))

    for package, entry in sorted(apt_listed.items()):
        if package not in apt_installed:
            problems.append(
                f"{package} (apt) is in the manifest but not installed by the Dockerfile."
            )
        problems += _entry_problems(package, entry, permitted, ("package",))
    return problems


def main(argv: list[str]) -> int:
    dockerfile = Path(argv[1]) if len(argv) > 1 else ROOT / "infra/docker/Dockerfile.worker"
    manifest_path = Path(argv[2]) if len(argv) > 2 else ROOT / "infra/tools-manifest.json"
    problems = check(dockerfile.read_text(), json.loads(manifest_path.read_text()))
    if problems:
        print("Tools manifest check FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    tools = json.loads(manifest_path.read_text())["tools"]
    print(f"Tools manifest check passed ({len(tools)} tool(s)):")
    for t in tools:
        print(f"  {t['name']} {t['version']} ({t['licence']})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Keeps the worker's external tools honest (ADR-0002).

licence_check.py covers Python packages; this covers the Go binaries the
worker image builds. Fails when:

- a `go install module@version` in Dockerfile.worker is not in
  infra/tools-manifest.json, or the versions differ;
- a manifest entry has a licence outside `permitted_licences`
  (so adding, say, an AGPL tool needs a deliberate manifest change that
  this check then rejects);
- a manifest entry is no longer installed (stale manifest).

Usage: python infra/scripts/tools_manifest_check.py [dockerfile] [manifest]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GO_INSTALL = re.compile(r"go\s+install\s+(?P<module>[^\s@]+)@(?P<version>[^\s\\&;]+)")


def installed_modules(dockerfile_text: str) -> dict[str, str]:
    return {m["module"]: m["version"] for m in GO_INSTALL.finditer(dockerfile_text)}


def check(dockerfile_text: str, manifest: dict) -> list[str]:
    problems: list[str] = []
    permitted = set(manifest.get("permitted_licences", []))
    listed = {t["module"]: t for t in manifest.get("tools", [])}
    installed = installed_modules(dockerfile_text)

    for module, version in sorted(installed.items()):
        entry = listed.get(module)
        if entry is None:
            problems.append(f"{module}@{version} is installed but not in the tools manifest.")
            continue
        if entry.get("version") != version:
            problems.append(
                f"{module}: Dockerfile installs {version}, manifest says {entry.get('version')}."
            )
    for module, entry in sorted(listed.items()):
        if module not in installed:
            problems.append(f"{module} is in the manifest but not installed by the Dockerfile.")
        if entry.get("licence") not in permitted:
            problems.append(
                f"{entry.get('name', module)}: licence {entry.get('licence')!r} is not permitted "
                f"({', '.join(sorted(permitted))})."
            )
        for key in ("name", "version", "licence", "source", "used_for"):
            if not entry.get(key):
                problems.append(f"{module}: manifest entry is missing '{key}'.")
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

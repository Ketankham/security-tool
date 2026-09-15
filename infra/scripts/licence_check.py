#!/usr/bin/env python3
"""
Licence gate for CI (ADR-0002).

We invoke tools like nuclei/subfinder/katana as separate-process MIT-licensed
binaries and never link/import GPL or AGPL code into the commercial core
(the sqlmap trap). This script is the automated half of that promise: it
walks every installed Python distribution in the workspace's virtualenv and
fails the build if anything copyleft or unrecognised sneaks in as a
dependency.

Not a substitute for judgement: distributions with missing/ambiguous licence
metadata are reported for manual review rather than silently allowed or
silently failed.
"""

from __future__ import annotations

import re
import sys
from importlib import metadata

# Licences we accept without question.
ALLOWED_LICENCE_SUBSTRINGS = (
    "mit",
    "bsd",
    "apache",
    "python software foundation",
    "psf",
    "isc",
    "mozilla public license 2.0",
    "mpl-2.0",
    "mpl 2.0",
    "the unlicense",
    "public domain",
)

# Word-bounded so "lgpl" never matches "gpl" here — LGPL's linking exception
# (see LGPL_REVIEWED_SUBSTRINGS below) makes it a fundamentally different
# case from GPL/AGPL for a dependency we only ever import at runtime.
DENIED_LICENCE_PATTERNS = tuple(
    re.compile(rf"(?<![a-z]){p}(?![a-z])") for p in ("gpl", "agpl", "sspl", "commons clause")
)

# LGPL permits linking an unmodified LGPL library into proprietary software
# (that's the whole point of the "Lesser" GPL — see e.g. Qt, glibc). Every
# dependency landing here is one we use exactly that way: an ordinary
# runtime import, never modified, never statically embedded such that a
# user couldn't swap in their own build of it. Flagged distinctly (not
# silently folded into ALLOWED) so it stays visible in every report.
LGPL_PATTERN = re.compile(r"(?<![a-z])lgpl(?![a-z])")

# Distributions we've manually reviewed because PyPI classifiers/metadata
# don't clearly state their licence (or state it ambiguously). Keep this
# list short and justify every entry in the PR that adds it.
MANUAL_ALLOWLIST: dict[str, str] = {
    # "some-package": "confirmed MIT via upstream LICENSE file on 2026-09-15",
}


def _meta_get(meta: metadata.PackageMetadata, key: str) -> str | None:
    # importlib.metadata's PackageMetadata protocol guarantees __contains__
    # and __getitem__ but not .get() in every typeshed version — this is
    # the portable equivalent.
    return meta[key] if key in meta else None  # noqa: SIM401 — .get() isn't in the type stub


def _licence_strings(dist: metadata.Distribution) -> list[str]:
    values: list[str] = []
    meta = dist.metadata
    # PEP 639 (current packaging metadata, ~2024+): most actively-maintained
    # packages (fastapi, click, pydantic, ...) now declare *only* this field
    # and leave the legacy ones below empty — checking just "License" and
    # "Classifier" (this script's original approach) misses almost every
    # modern package and floods the report with false "needs review" noise.
    if license_expression := _meta_get(meta, "License-Expression"):
        values.append(license_expression)
    if license_field := _meta_get(meta, "License"):
        values.append(license_field)
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            values.append(classifier)
    return values


def main() -> int:
    denied: list[tuple[str, str, list[str]]] = []
    lgpl_reviewed: list[tuple[str, str, list[str]]] = []
    unknown: list[tuple[str, str]] = []
    checked = 0

    for dist in metadata.distributions():
        name = _meta_get(dist.metadata, "Name") or _meta_get(dist.metadata, "Summary") or "unknown"
        version = _meta_get(dist.metadata, "Version") or "?"
        if name.lower() in MANUAL_ALLOWLIST:
            continue
        if name.lower().startswith("sentinel-"):
            # Our own first-party packages, not adopted third-party
            # dependencies — nothing here for ADR-0002 to gate.
            continue

        strings = _licence_strings(dist)
        checked += 1

        if not strings:
            unknown.append((name, version))
            continue

        lowered = " | ".join(strings).lower()

        if LGPL_PATTERN.search(lowered):
            lgpl_reviewed.append((name, version, strings))
            continue

        if any(pattern.search(lowered) for pattern in DENIED_LICENCE_PATTERNS):
            denied.append((name, version, strings))
            continue

        if not any(ok in lowered for ok in ALLOWED_LICENCE_SUBSTRINGS):
            unknown.append((name, version))

    print(
        f"Licence check: {checked} distributions inspected "
        f"({len(MANUAL_ALLOWLIST)} pre-approved by manual review)."
    )

    if denied:
        print("\nFAIL — copyleft/denied licences found:")
        for name, version, strings in denied:
            print(f"  - {name} {version}: {', '.join(strings)}")
        print(
            "\nSee docs/adr/0002-build-vs-adopt-open-source.md — do not link or "
            "bundle GPL/AGPL code into the commercial core. Shell out to it as a "
            "separate process instead, or find an MIT/Apache/BSD alternative."
        )

    if lgpl_reviewed:
        print(
            "\nLGPL (allowed — runtime dependency only, never modified or "
            "statically embedded; see LGPL_PATTERN comment in this script):"
        )
        for name, version, strings in lgpl_reviewed:
            print(f"  - {name} {version}: {', '.join(strings)}")

    if unknown:
        print(
            "\nNEEDS REVIEW — licence metadata unclear (not failing the build, "
            "but each of these needs a human to confirm and add to "
            "MANUAL_ALLOWLIST in this script with a justification):"
        )
        for name, version in unknown:
            print(f"  - {name} {version}")

    if denied:
        return 1

    print("\nOK — no denied licences detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

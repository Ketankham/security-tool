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

# Substrings that fail the build outright, no matter what else is in the field.
DENIED_LICENCE_SUBSTRINGS = (
    "gpl",
    "agpl",
    "sspl",
    "commons clause",
)

# Distributions we've manually reviewed because PyPI classifiers/metadata
# don't clearly state their licence (or state it ambiguously). Keep this
# list short and justify every entry in the PR that adds it.
MANUAL_ALLOWLIST: dict[str, str] = {
    # "some-package": "confirmed MIT via upstream LICENSE file on 2026-09-15",
}


def _licence_strings(dist: metadata.Distribution) -> list[str]:
    values: list[str] = []
    meta = dist.metadata
    if meta.get("License"):
        values.append(meta["License"])
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            values.append(classifier)
    return values


def main() -> int:
    denied: list[tuple[str, str, list[str]]] = []
    unknown: list[tuple[str, str]] = []
    checked = 0

    for dist in metadata.distributions():
        name = dist.metadata.get("Name") or dist.metadata.get("Summary") or "unknown"
        version = dist.metadata.get("Version", "?")
        if name.lower() in MANUAL_ALLOWLIST:
            continue

        strings = _licence_strings(dist)
        checked += 1

        if not strings:
            unknown.append((name, version))
            continue

        lowered = " | ".join(strings).lower()

        if any(bad in lowered for bad in DENIED_LICENCE_SUBSTRINGS):
            denied.append((name, version, strings))
            continue

        if not any(ok in lowered for ok in ALLOWED_LICENCE_SUBSTRINGS):
            unknown.append((name, version))

    print(f"Licence check: {checked} distributions inspected "
          f"({len(MANUAL_ALLOWLIST)} pre-approved by manual review).")

    if denied:
        print("\nFAIL — copyleft/denied licences found:")
        for name, version, strings in denied:
            print(f"  - {name} {version}: {', '.join(strings)}")
        print(
            "\nSee docs/adr/0002-build-vs-adopt-open-source.md — do not link or "
            "bundle GPL/AGPL code into the commercial core. Shell out to it as a "
            "separate process instead, or find an MIT/Apache/BSD alternative."
        )

    if unknown:
        print("\nNEEDS REVIEW — licence metadata unclear (not failing the build, "
              "but each of these needs a human to confirm and add to "
              "MANUAL_ALLOWLIST in this script with a justification):")
        for name, version in unknown:
            print(f"  - {name} {version}")

    if denied:
        return 1

    print("\nOK — no denied licences detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

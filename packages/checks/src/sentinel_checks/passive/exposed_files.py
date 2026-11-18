"""Exposed files and endpoints (docs/03 §4).

Only read-only GET/HEAD requests to well-known paths on hosts the crawl
reached. Three safeguards keep it honest and safe:

- a file is reported only if its *content matches the file's signature*
  (a ``ref: refs/heads/..`` line for .git/HEAD, KEY=value lines for .env, ...).
  A status code alone proves nothing: many sites answer 200 to every path;
- a response identical to a made-up path's response is ignored (catch-all);
- probes that could return a client's secrets (.env, .git/config, config
  backups, .htpasswd) are stored *without* the response body, and findings
  list only variable names, never values. Archive/dump probes use HEAD, so a
  multi-gigabyte backup is never downloaded.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from sentinel_core.http_engine import EngineResponse

from .models import EvidenceRef, PassiveCandidate, PassiveContext, curl_for, hget

_ENV_LINE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\S")
_ARCHIVE_TYPES = (
    "application/zip",
    "application/x-zip",
    "application/x-gzip",
    "application/gzip",
    "application/x-tar",
    "application/x-7z",
    "application/x-rar",
    "application/octet-stream",
    "application/sql",
    "application/x-sql",
)


def _text(response: EngineResponse) -> str:
    return response.body[:200_000].decode("utf-8", errors="replace")


def _looks_html(text: str) -> bool:
    head = text[:600].lower()
    return "<html" in head or "<!doctype html" in head


def validate_env(response: EngineResponse) -> str | None:
    text = _text(response)
    if _looks_html(text):
        return None
    names = _ENV_LINE.findall(text)
    if len(names) < 2:
        return None
    return f"{len(names)} settings, for example {', '.join(names[:4])} (values not stored)"


def validate_git_head(response: EngineResponse) -> str | None:
    text = _text(response).strip()
    if re.match(r"^ref: refs/", text) or re.fullmatch(r"[0-9a-f]{40}", text):
        return "a Git HEAD pointer (the site's source repository is downloadable)"
    return None


def validate_git_config(response: EngineResponse) -> str | None:
    text = _text(response)
    if "[core]" in text and "repositoryformatversion" in text:
        return "a Git config file (its remote URL may contain credentials; not stored)"
    return None


def validate_ds_store(response: EngineResponse) -> str | None:
    if response.body.startswith(b"\x00\x00\x00\x01Bud1"):
        return "a macOS .DS_Store file listing the folder's file names"
    return None


def validate_htpasswd(response: EngineResponse) -> str | None:
    text = _text(response)
    if _looks_html(text):
        return None
    if re.search(r"(?m)^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13})", text):
        return "an .htpasswd file with password hashes (not stored)"
    return None


def validate_wp_config(response: EngineResponse) -> str | None:
    text = _text(response)
    if "DB_PASSWORD" in text and "DB_NAME" in text:
        return "a WordPress config file with database credentials (not stored)"
    return None


def validate_phpinfo(response: EngineResponse) -> str | None:
    text = _text(response)
    if "phpinfo()" in text or ("PHP Version" in text and "<table" in text):
        return "a phpinfo() page (PHP version, paths and environment)"
    return None


def validate_server_status(response: EngineResponse) -> str | None:
    if "Apache Server Status" in _text(response):
        return "the Apache server-status page (live requests and client IPs)"
    return None


def validate_actuator_env(response: EngineResponse) -> str | None:
    try:
        doc = json.loads(_text(response))
    except ValueError:
        return None
    if isinstance(doc, dict) and ("propertySources" in doc or "activeProfiles" in doc):
        return "the Spring Boot /actuator/env endpoint (configuration, possibly secrets)"
    return None


def validate_api_docs(response: EngineResponse) -> str | None:
    try:
        doc = json.loads(_text(response))
    except ValueError:
        return None
    if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and "paths" in doc:
        paths = doc["paths"]
        count = len(paths) if isinstance(paths, dict) else 0
        return f"an API description listing {count} path(s)"
    return None


def validate_archive_head(response: EngineResponse) -> str | None:
    """HEAD only: a big download is recognised by its headers, never fetched."""
    content_type = (hget(response.headers, "content-type") or "").lower().split(";")[0].strip()
    length = hget(response.headers, "content-length") or ""
    if (
        response.status_code == 200
        and content_type in _ARCHIVE_TYPES
        and length.isdigit()
        and int(length) >= 1024
    ):
        return f"a downloadable file ({content_type}, {int(length):,} bytes)"
    return None


@dataclass(frozen=True, slots=True)
class Probe:
    rule_id: str
    path: str
    title: str
    severity: str
    cwe: list[int]
    validate: Callable[[EngineResponse], str | None]
    fix: str
    steps: list[str]
    method: str = "GET"
    # Don't keep the response body as evidence (it may hold secrets).
    withhold: bool = False
    owasp: str = "A05:2021"


_REMOVE = "Remove the file from the web root and block access to it at the web server."
_ROTATE = "Treat every secret in it as leaked: rotate them after removing the file."


def _env(path: str) -> Probe:
    return Probe(
        "exposed.env_file",
        path,
        "Environment file (.env) is publicly downloadable",
        "critical",
        [538, 200],
        validate_env,
        _REMOVE + " " + _ROTATE,
        [
            "Delete the file from the public web root (deploy it outside the document root).",
            "Deny dotfiles in the web server (nginx: location ~ /\\. { deny all; }).",
            "Rotate the database passwords, API keys and app secrets that were in it.",
        ],
        withhold=True,
    )


def _archive(path: str) -> Probe:
    return Probe(
        "exposed.backup_file",
        path,
        "Backup or dump file is publicly downloadable",
        "high",
        [530],
        validate_archive_head,
        _REMOVE,
        [
            "Delete the file from the web root and store backups outside it.",
            "Assume its contents (code, database rows, secrets) are public and rotate secrets.",
        ],
        method="HEAD",
    )


PROBES: list[Probe] = [
    _env("/.env"),
    _env("/.env.local"),
    _env("/.env.production"),
    _env("/.env.backup"),
    Probe(
        "exposed.git_repository",
        "/.git/HEAD",
        "Git repository is publicly downloadable",
        "high",
        [527],
        validate_git_head,
        _REMOVE,
        [
            "Remove the .git folder from the web root (deploy build output, not a checkout).",
            "Deny access to /.git at the web server.",
            "Assume the source code and any committed secrets are public; rotate secrets.",
        ],
    ),
    Probe(
        "exposed.git_config",
        "/.git/config",
        "Git configuration is publicly downloadable",
        "high",
        [527],
        validate_git_config,
        _REMOVE,
        [
            "Remove /.git from the web root and deny access to it.",
            "Rotate any credentials in remote URLs.",
        ],
        withhold=True,
    ),
    Probe(
        "exposed.ds_store",
        "/.DS_Store",
        "macOS .DS_Store file is publicly downloadable",
        "low",
        [538],
        validate_ds_store,
        _REMOVE,
        ["Delete .DS_Store files from the web root.", "Deny dotfiles at the web server."],
    ),
    Probe(
        "exposed.htpasswd",
        "/.htpasswd",
        ".htpasswd password file is publicly downloadable",
        "high",
        [538],
        validate_htpasswd,
        _REMOVE + " " + _ROTATE,
        ["Move .htpasswd outside the web root.", "Reset the passwords it protected."],
        withhold=True,
    ),
    Probe(
        "exposed.config_backup",
        "/wp-config.php.bak",
        "Application config backup is publicly downloadable",
        "critical",
        [530, 200],
        validate_wp_config,
        _REMOVE + " " + _ROTATE,
        [
            "Delete editor/backup copies of config files from the web root.",
            "Rotate the database password.",
        ],
        withhold=True,
    ),
    Probe(
        "exposed.config_backup",
        "/wp-config.php.old",
        "Application config backup is publicly downloadable",
        "critical",
        [530, 200],
        validate_wp_config,
        _REMOVE + " " + _ROTATE,
        [
            "Delete editor/backup copies of config files from the web root.",
            "Rotate the database password.",
        ],
        withhold=True,
    ),
    Probe(
        "exposed.phpinfo",
        "/phpinfo.php",
        "phpinfo() page is publicly accessible",
        "medium",
        [200],
        validate_phpinfo,
        "Delete the phpinfo page.",
        ["Remove phpinfo.php / info.php from production."],
    ),
    Probe(
        "exposed.phpinfo",
        "/info.php",
        "phpinfo() page is publicly accessible",
        "medium",
        [200],
        validate_phpinfo,
        "Delete the phpinfo page.",
        ["Remove phpinfo.php / info.php from production."],
    ),
    Probe(
        "exposed.server_status",
        "/server-status",
        "Apache server-status page is publicly accessible",
        "medium",
        [200],
        validate_server_status,
        "Restrict /server-status to localhost or disable mod_status.",
        ["In the Apache config: <Location /server-status> Require local </Location>"],
    ),
    Probe(
        "exposed.actuator_env",
        "/actuator/env",
        "Spring Boot actuator /env endpoint is publicly accessible",
        "high",
        [215, 200],
        validate_actuator_env,
        "Do not expose actuator endpoints publicly; require authentication.",
        [
            "Set management.endpoints.web.exposure.include to only health (or nothing).",
            "Put the management port behind the network or require authentication.",
        ],
        withhold=True,
    ),
    Probe(
        "exposed.api_docs",
        "/openapi.json",
        "API documentation is publicly accessible",
        "info",
        [200],
        validate_api_docs,
        "Confirm the API description is meant to be public; otherwise require authentication.",
        ["Restrict /openapi.json, /swagger.json and the docs UI to authenticated users."],
        owasp="A05:2021",
    ),
    Probe(
        "exposed.api_docs",
        "/swagger.json",
        "API documentation is publicly accessible",
        "info",
        [200],
        validate_api_docs,
        "Confirm the API description is meant to be public; otherwise require authentication.",
        ["Restrict /openapi.json, /swagger.json and the docs UI to authenticated users."],
    ),
    Probe(
        "exposed.api_docs",
        "/v2/api-docs",
        "API documentation is publicly accessible",
        "info",
        [200],
        validate_api_docs,
        "Confirm the API description is meant to be public; otherwise require authentication.",
        ["Restrict the API docs endpoints to authenticated users."],
    ),
    _archive("/backup.zip"),
    _archive("/site.zip"),
    _archive("/backup.sql"),
    _archive("/dump.sql"),
]


async def check_exposed_files(ctx: PassiveContext) -> list[PassiveCandidate]:
    candidates: list[PassiveCandidate] = []
    probed = 0
    for origin in ctx.origins:
        if origin in ctx.unreachable:
            continue
        random_path = f"/sentinel-probe-{uuid.uuid4().hex[:10]}"
        baseline_get = await ctx.fetch("GET", origin + random_path)
        baseline_head = await ctx.fetch("HEAD", origin + random_path)
        if baseline_get is None and baseline_head is None:
            ctx.log("warn", f"Exposed-file check: {origin} did not answer; skipping its probes.")
            continue
        if baseline_get is not None and baseline_get.status_code == 200:
            ctx.log(
                "info",
                f"Exposed-file check on {origin}: a made-up path answers 200 (catch-all), so "
                "only responses whose content matches a file's signature count.",
            )
        for probe in PROBES:
            url = origin + probe.path
            baseline = baseline_head if probe.method == "HEAD" else baseline_get
            response = await ctx.fetch(probe.method, url, withhold_body=probe.withhold)
            if response is None:
                continue
            probed += 1
            if response.status_code != 200:
                continue
            if baseline is not None and baseline.status_code == 200:
                same = (
                    response.body == baseline.body
                    if probe.method == "GET"
                    else hget(response.headers, "content-type")
                    == hget(baseline.headers, "content-type")
                )
                if same:
                    continue  # the site answers everything the same way
            matched = probe.validate(response)
            if matched is None:
                continue
            ctx.log("warn", f"Exposed file: {url} is {matched}")

            def make_reproduce(probe: Probe = probe, url: str = url):
                async def reproduce() -> bool:
                    again = await ctx.fetch(probe.method, url, withhold_body=probe.withhold)
                    return (
                        again is not None
                        and again.status_code == 200
                        and (probe.validate(again) is not None)
                    )

                return reproduce

            candidates.append(
                PassiveCandidate(
                    rule_id=probe.rule_id,
                    title=f"{probe.title} ({origin.split('://', 1)[1]}{probe.path})",
                    severity=probe.severity,
                    cwe=probe.cwe,
                    owasp=probe.owasp,
                    origin=origin,
                    subject=probe.path,
                    narrative=(
                        f"{url} can be fetched by anyone without logging in, and it is {matched}."
                        + (
                            " The response body was deliberately not stored here, to avoid "
                            "copying secrets."
                            if probe.withhold
                            else ""
                        )
                    ),
                    remediation_summary=probe.fix,
                    remediation_steps=probe.steps,
                    reproduction_curl=curl_for(url, method=probe.method),
                    reproduction_expect=(
                        "It answers 200 with the content described above instead of 404."
                    ),
                    evidence=[
                        EvidenceRef(
                            transcript_id=response.transcript_id,
                            method=probe.method,
                            url=url,
                            status_code=response.status_code,
                            role="exposed-file-response",
                            note=f"{probe.method} {url} answered {response.status_code}: {matched}",
                        )
                    ],
                    reproduce=make_reproduce(),
                )
            )
    ctx.log(
        "info",
        f"Exposed-file check: {probed} well-known path(s) probed, {len(candidates)} exposed.",
    )
    return candidates

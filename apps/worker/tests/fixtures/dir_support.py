"""Helpers shared by the directory brute force tests: recon results that point
at local sites, wordlists of a few entries, a fake ``ffuf`` binary, an engine,
and a recording log."""

from __future__ import annotations

import os
import stat
import sys
import textwrap
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sentinel_core.scope_guard import ScopeGuard
from sentinel_core.scope_guard import ScopeRule as CoreScopeRule
from sentinel_db.models import Organization, Scan, ScanAuthorisation, Target
from sentinel_recon import DiscoveredAsset, HttpProbeResult, ReconResult, wordlists
from sentinel_worker_app.config import Settings
from sentinel_worker_app.substrate import build_http_engine

ALL_HOSTS = {"127.0.0.1", "localhost", "vm", "runsc"}  # the names this sandbox resolves


def recon_for(*hosts: tuple[str, int, str], root: str | None = None) -> ReconResult:
    """A recon result with one live, in-scope asset per ``(name, port, ip)``."""
    assets = [
        DiscoveredAsset(
            host=name,
            source="root_domain" if name == (root or hosts[0][0]) else "subfinder",
            ips=[ip],
            http_probes=[
                HttpProbeResult(
                    url=f"http://{name}:{port}", status_code=200, title=None, server=None
                )
            ],
        )
        for name, port, ip in hosts
    ]
    return ReconResult(
        root_domain=root or hosts[0][0],
        assets=assets,
        tool_availability={},
        wildcard_dns_suspected=False,
    )


def guard_for(hosts=ALL_HOSTS, rules: list[CoreScopeRule] | None = None) -> ScopeGuard:
    return ScopeGuard(allowed_hosts=set(hosts), rules=rules or [], target_ownership_verified=True)


def rule(kind: str, pattern: str, effect: str = "exclude") -> CoreScopeRule:
    return CoreScopeRule(kind=kind, pattern=pattern, effect=effect, label=pattern)


def wordlist_loader(*pairs: tuple[str, str], bulk: int = 0, name: str = "sentinel-core"):
    """A ``load_wordlist`` stand-in with just these (category, path) entries,
    plus ``bulk`` filler entries (so ffuf's own stop rules, which need 50+
    requests, can be exercised)."""
    entries = [wordlists.Entry(category=c, path=p) for c, p in pairs]
    entries += [wordlists.Entry(category="common", path=f"filler-{i:04d}") for i in range(bulk)]
    wl = wordlists.Wordlist(name=name, sha256="ab" * 32, entries=entries)

    def load(requested: str):
        return wl if requested in (name, "sentinel-core") else None

    return load


def make_engine(scope_guard, redis_client, tmp_path: Path, scan_id, *, allow_private=True, rps=200):
    settings = Settings(
        storage_local_path=str(tmp_path / "transcripts"),
        allow_private_addresses=allow_private,
    )
    return build_http_engine(
        scope_guard=scope_guard,
        redis_client=redis_client,
        settings=settings,
        target_id=f"target-{uuid.uuid4().hex[:8]}",
        scan_id=str(scan_id),
        requests_per_second=rps,
    )


class RecordingLog:
    """Stands in for ScanLog; ``on_add`` lets a test react to a log line."""

    def __init__(self, on_add=None) -> None:
        self.lines: list[tuple[str, str, str]] = []
        self.on_add = on_add

    def add(self, stage: str, message: str, *, level: str = "info", **_data) -> None:
        self.lines.append((stage, level, message))
        if self.on_add is not None:
            self.on_add(stage, level, message)

    def add_secrets(self, _values) -> None:
        return None

    @property
    def messages(self) -> list[str]:
        return [m for _s, _l, m in self.lines]

    def has(self, text: str) -> bool:
        return any(text in m for m in self.messages)


class FakeCancel:
    """A CancelWatch stand-in: set ``by`` to cancel."""

    def __init__(self) -> None:
        self.by: str | None = None

    async def requested(self) -> str | None:
        return self.by

    async def raise_if_cancelled(self) -> None:
        from sentinel_worker_app.cancel import ScanCancelled

        if self.by is not None:
            raise ScanCancelled(self.by)


async def scan_with_authorisation(
    session,
    options: dict,
    *,
    root_domain: str = "127.0.0.1",
    authorised: bool = True,
    tools: list[str] | None = None,
    username: str = "alice",
    all_ports_confirmed: bool = False,
    target_environment: str = "production",
) -> tuple[Scan, Target]:
    org = Organization(name="D", slug=f"d-{uuid.uuid4().hex[:8]}", wrapped_data_key=b"k")
    session.add(org)
    await session.flush()
    target = Target(
        organization_id=org.id,
        root_domain=root_domain,
        display_name="Local site",
        ownership_verified=True,
        authorization_accepted=True,
    )
    session.add(target)
    await session.flush()
    scan = Scan(target_id=target.id, options=options, requested_by=username)
    session.add(scan)
    await session.flush()
    if authorised:
        session.add(
            ScanAuthorisation(
                scan_id=scan.id,
                target_id=target.id,
                username=username,
                accepted_at=datetime(2026, 11, 25, 9, 30, tzinfo=UTC),
                statement_version="1",
                statement_text="I confirm Acme Ltd has authorised ...",
                client_name="Acme Ltd",
                target_name=root_domain,
                tools=tools or ["dir_bruteforce"],
                all_ports_confirmed=all_ports_confirmed,
                target_environment=target_environment,
                options_snapshot={},
            )
        )
    await session.commit()
    return scan, target


# --- A fake ffuf ---------------------------------------------------------------


def install_fake_ffuf(tmp_path: Path, monkeypatch, body: str, *, keep_real_path=False) -> Path:
    """Puts a Python script named ``ffuf`` first on PATH. ``body`` runs after
    the arguments are parsed into ``args`` (a list), ``wordlist`` (the -w file's
    path), ``paths`` (its lines) and ``emit(path, status, ...)`` (prints one
    ffuf -json hit). It also writes its argv and the wordlist's content to
    $FAKE_FFUF_CAPTURE (a directory) and its pid to capture/pid."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "ffuf"
    prelude = textwrap.dedent(
        f"""\
        #!{sys.executable}
        import base64, json, os, sys, time
        args = sys.argv[1:]
        if args[:1] == ["-V"]:
            print("ffuf version: 2.1.0-dev")
            sys.exit(0)
        wordlist = args[args.index("-w") + 1].rsplit(":", 1)[0]
        paths = open(wordlist).read().split("\\n")
        paths = [p for p in paths if p]
        capture = os.environ.get("FAKE_FFUF_CAPTURE")
        if capture:
            os.makedirs(capture, exist_ok=True)
            with open(os.path.join(capture, "args.json"), "w") as f:
                json.dump(args, f)
            with open(os.path.join(capture, "wordlist.txt"), "w") as f:
                f.write("\\n".join(paths))
            with open(os.path.join(capture, "pid"), "w") as f:
                f.write(str(os.getpid()))
            with open(os.path.join(capture, "cwd"), "w") as f:
                f.write(os.getcwd() + "\\n" + os.environ.get("HOME", ""))

        def emit(path, status=200, length=10, words=2, lines=1, ctype="text/html", redirect=""):
            print(json.dumps({{
                "input": {{"FFUFHASH": "x", "FUZZ": base64.b64encode(path.encode()).decode()}},
                "position": 1, "status": status, "length": length, "words": words,
                "lines": lines, "content-type": ctype, "redirectlocation": redirect,
                "url": "http://pinned/" + path, "duration": 1, "host": "pinned",
            }}), flush=True)
        """
    )
    script.write_text(prelude + "\n" + textwrap.dedent(body))
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    path = str(bin_dir) if not keep_real_path else f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
    monkeypatch.setenv("PATH", path)
    capture = tmp_path / "capture"
    monkeypatch.setenv("FAKE_FFUF_CAPTURE", str(capture))
    return capture


# --- Running the step against a database ---------------------------------------


class StepResult:
    def __init__(self, stats, log, scan_id, target_id, factory, error=None) -> None:
        self.stats = stats
        self.log = log
        self.scan_id = scan_id
        self.target_id = target_id
        self.factory = factory
        self.error = error

    async def rows(self):
        from sentinel_db.models import DiscoveredPath
        from sqlalchemy import select

        async with self.factory() as session:
            return list(
                (
                    await session.execute(
                        select(DiscoveredPath)
                        .where(DiscoveredPath.scan_id == self.scan_id)
                        .order_by(DiscoveredPath.path)
                    )
                )
                .scalars()
                .all()
            )

    async def tool_runs(self):
        from sentinel_db.models import ToolRunRecord
        from sqlalchemy import select

        async with self.factory() as session:
            return list(
                (
                    await session.execute(
                        select(ToolRunRecord)
                        .where(ToolRunRecord.scan_id == self.scan_id)
                        .order_by(ToolRunRecord.seq)
                    )
                )
                .scalars()
                .all()
            )

    async def scan(self):
        async with self.factory() as session:
            return await session.get(Scan, self.scan_id)

    async def findings(self):
        from sentinel_db.models import Finding
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        async with self.factory() as session:
            return list(
                (
                    await session.execute(
                        select(Finding)
                        .where(Finding.scan_id == self.scan_id)
                        .options(selectinload(Finding.evidence), selectinload(Finding.verification))
                    )
                )
                .scalars()
                .all()
            )


async def run_step(
    db_engine,
    redis_client,
    tmp_path: Path,
    recon: ReconResult,
    loader,
    *,
    rules: list[CoreScopeRule] | None = None,
    hosts=ALL_HOSTS,
    cancel=None,
    log=None,
    allow_private: bool = True,
    engine_private: bool | None = None,
    options: dict | None = None,
    **kwargs,
) -> StepResult:
    """Runs run_dir_bruteforce for a fresh authorised scan and returns what it
    left behind. Exceptions (a cancel) are kept in ``.error``."""
    from sentinel_worker_app.dir_bruteforce_adapter import run_dir_bruteforce
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    log = log or RecordingLog()
    cancel = cancel or FakeCancel()
    guard = guard_for(hosts, rules)
    error = None
    async with factory() as session:
        scan, target = await scan_with_authorisation(
            session, options or {"dir_bruteforce": True}, root_domain=recon.root_domain
        )
        engine = make_engine(
            guard,
            redis_client,
            tmp_path,
            scan.id,
            allow_private=allow_private if engine_private is None else engine_private,
        )
        stats = None
        try:
            stats = await run_dir_bruteforce(
                session,
                scan,
                target,
                recon,
                guard,
                engine,
                kwargs.pop("profile", "light"),
                kwargs.pop("rps", 50.0),
                cancel,
                log,
                kwargs.pop("seq", 1),
                authorised_by="alice",
                allow_private=allow_private,
                load_wordlist=loader,
                **kwargs,
            )
        except BaseException as exc:  # noqa: BLE001 — the test inspects it
            error = exc
        finally:
            await engine.aclose()
    return StepResult(stats, log, scan.id, target.id, factory, error)


async def everything_stored(db_engine, *directories: Path) -> str:
    """Every row of every table (as JSON text) and every stored file under
    ``directories``, in one string: for asserting a secret was never kept."""
    from sqlalchemy import text

    chunks: list[str] = []
    async with db_engine.connect() as conn:
        tables = (
            (
                await conn.execute(
                    text(
                        "select table_name from information_schema.tables "
                        "where table_schema='public'"
                    )
                )
            )
            .scalars()
            .all()
        )
        for table in tables:
            rows = (
                await conn.execute(text(f'select row_to_json(t)::text from "{table}" t'))
            ).scalars()
            chunks.extend(rows)
    for directory in directories:
        for path in Path(directory).rglob("*"):
            if path.is_file():
                chunks.append(path.read_bytes().decode("utf-8", errors="replace"))
    return "\n".join(chunks)

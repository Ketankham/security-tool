"""Scan lifecycle endpoints. Creating a scan transitions nothing by itself —
the worker (apps/worker, Task via Celery) owns walking the state machine
(sentinel_core.state_machine.ScanStateMachine). This router only creates the
QUEUED row and asks the broker to pick it up (docs/01 §5).

Active tools (directory brute force, port scanning) are validated here and the
"I'm authorised" confirmation is stored with the scan in one transaction,
before the scan is dispatched: the worker refuses to run an active tool for a
scan that has no such record.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import structlog
from fastapi import APIRouter, Body, Depends, HTTPException, status
from redis import asyncio as aioredis
from sentinel_core import authorisation as authorisation_text
from sentinel_core import scan_options
from sentinel_core.state_machine import TERMINAL_STATES, ScanState
from sentinel_db.models import Organization, Scan, ScanAuthorisation, Target
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..celery_client import dispatch_scan
from ..config import get_settings
from ..deps import get_current_org, get_owned_scan, get_owned_target, get_session
from ..identity import Identity, get_identity
from ..schemas.scan import (
    AuthorisationIn,
    ScanAuthorisationOut,
    ScanCreate,
    ScanOut,
    ScanRetry,
)

log = structlog.get_logger(__name__)

# The worker watches this key (apps/worker cancel.py): any value means "stop".
CANCEL_KEY_PREFIX = "sentinel:scan-cancel:"
CANCEL_KEY_TTL_S = 86400

router = APIRouter(tags=["scans"])


def _validate_active_tools(
    payload: ScanCreate, target: Target, identity: Identity | None
) -> list[str]:
    """The active tools this request asks for, after refusing anything that
    must not run. Checks run in this order and each has its own message, so
    the dashboard can show exactly what to fix. Returns [] for a passive scan."""
    requested = scan_options.active_tools(payload.model_dump())
    labels = scan_options.ACTIVE_TOOL_LABELS

    for tool in requested:
        if tool not in scan_options.IMPLEMENTED_ACTIVE_TOOLS:
            raise HTTPException(422, f"{labels[tool]} is not available yet.")
    if payload.all_ports and not payload.port_scan:
        raise HTTPException(
            422,
            "All 65,535 ports needs port scanning switched on.",
        )
    if payload.all_ports and payload.recon_profile != "full":
        raise HTTPException(
            422,
            "All 65,535 ports is only available on the Full recon profile.",
        )
    if payload.wordlist == "seclists-common" and (
        payload.recon_profile != "full" or not payload.dir_bruteforce
    ):
        raise HTTPException(
            422,
            "The SecLists wordlist is only available for directory brute forcing "
            "on the Full recon profile.",
        )
    if not requested:
        return []

    if identity is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Active tools need a signed-in user, and this request has no verified identity. "
            "Open Sentinel through its sign-in page.",
        )
    confirmation = payload.authorisation
    if confirmation is None or not confirmation.accepted or not confirmation.client_name:
        raise HTTPException(
            422,
            "Active tools need the 'I'm authorised' confirmation: "
            "name the client and tick the box.",
        )
    if confirmation.statement_version != authorisation_text.STATEMENT_VERSION:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "The authorisation statement has changed "
            f"(now version {authorisation_text.STATEMENT_VERSION}). "
            "Reload the page and confirm again.",
        )
    if payload.all_ports and not confirmation.all_ports_confirmed:
        raise HTTPException(
            422,
            "Scanning all 65,535 ports needs its own confirmation.",
        )
    return requested


def _environment(payload: ScanCreate, target: Target) -> str:
    return payload.target_environment or ("production" if target.is_production else "staging")


def _options_of(payload: ScanCreate, target: Target) -> dict:
    return {
        "speed": payload.speed,
        "depth": payload.depth,
        "recon_profile": payload.recon_profile,
        "dir_bruteforce": payload.dir_bruteforce,
        "port_scan": payload.port_scan,
        "all_ports": payload.all_ports,
        "wordlist": payload.wordlist,
        "target_environment": _environment(payload, target),
    }


def _authorisation_row(
    *,
    scan: Scan,
    target: Target,
    identity: Identity,
    confirmation: AuthorisationIn,
    tools: list[str],
    options: dict,
    carried_over_from: UUID | None = None,
) -> ScanAuthorisation:
    statement = authorisation_text.render(confirmation.client_name, target.root_domain)
    if "all_ports" in tools:
        statement += " " + authorisation_text.render_all_ports(target.root_domain)
    return ScanAuthorisation(
        scan_id=scan.id,
        target_id=target.id,
        username=identity.username,
        accepted_at=datetime.now(UTC),
        statement_version=confirmation.statement_version,
        statement_text=statement,
        client_name=confirmation.client_name,
        target_name=target.root_domain,
        tools=tools,
        all_ports_confirmed="all_ports" in tools and confirmation.all_ports_confirmed,
        target_environment=str(options.get("target_environment") or "production"),
        options_snapshot=dict(options),
        client_ip=identity.client_ip,
        user_agent=identity.user_agent,
        carried_over_from_scan_id=carried_over_from,
    )


@router.post(
    "/targets/{target_id}/scans", response_model=ScanOut, status_code=status.HTTP_201_CREATED
)
async def create_scan(
    payload: ScanCreate,
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
    identity: Identity | None = Depends(get_identity),
) -> Scan:
    if get_settings().require_ownership_verification and not target.is_scannable:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Target is not scannable yet — ownership must be verified and authorization "
            "accepted first (see docs/06-safety-legal-abuse.md §1).",
        )

    tools = _validate_active_tools(payload, target, identity)
    options = _options_of(payload, target)
    return await _start_scan(
        session,
        target,
        triggered_by=payload.triggered_by,
        options=options,
        identity=identity,
        tools=tools,
        confirmation=payload.authorisation,
    )


async def _start_scan(
    session: AsyncSession,
    target: Target,
    *,
    triggered_by: str,
    options: dict,
    identity: Identity | None = None,
    tools: list[str] | None = None,
    confirmation: AuthorisationIn | None = None,
    carried_over_from: UUID | None = None,
) -> Scan:
    scan = Scan(
        target_id=target.id,
        triggered_by=triggered_by,
        options=options,
        requested_by=identity.username if identity else None,
    )
    session.add(scan)
    if tools:
        # Same transaction as the scan, committed before dispatch: a scan that
        # asks for an active tool never exists without its authorisation record.
        assert identity is not None and confirmation is not None  # _validate_active_tools
        await session.flush()
        session.add(
            _authorisation_row(
                scan=scan,
                target=target,
                identity=identity,
                confirmation=confirmation,
                tools=tools,
                options=options,
                carried_over_from=carried_over_from,
            )
        )
    await session.commit()

    if not dispatch_scan(str(scan.id)):
        # Nothing will ever pick this scan up; say so now instead of leaving
        # it "Queued" forever. Retry works once the queue is back.
        scan.state = ScanState.FAILED
        scan.fail_reason = (
            "The scan could not be handed to the scan worker (the job queue is unreachable). "
            "Use Retry in a minute; if it keeps failing, check the redis and worker containers."
        )
        scan.finished_at = datetime.now(UTC)
        await session.commit()

    # Re-fetch with phases eagerly (selectin) loaded: assigning or reading
    # scan.phases directly here would trigger an implicit lazy load, which
    # AsyncSession forbids outside an explicit await — the same rule this
    # product's own crawler relies on to never do surprise I/O either.
    result = await session.execute(
        select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.phases))
    )
    return result.scalar_one()


_RETRY_OPTION_KEYS = (
    "speed",
    "depth",
    "recon_profile",
    "dir_bruteforce",
    "port_scan",
    "all_ports",
    "wordlist",
    "target_environment",
)


@router.post("/scans/{scan_id}/retry", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def retry_scan(
    scan_id: UUID,
    payload: ScanRetry | None = Body(default=None),
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
    identity: Identity | None = Depends(get_identity),
) -> Scan:
    """Start a fresh scan of the same target. The old scan stays as it was
    (its findings and failure reason are history); only a scan that has
    finished, one way or another, can be retried.

    A scan that used active tools is not retried silently: the record must name
    the person who launched *this* traffic, at the time it was launched,
    permission may have been withdrawn since, and a retry can be started by a
    different user. So the body must either confirm again (``authorisation``)
    or drop the tools (``drop_active_tools``)."""
    old = await _org_scan(session, scan_id, org)
    if old.state not in TERMINAL_STATES:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This scan is still running; wait for it to finish."
        )
    target = await session.get(Target, old.target_id)
    assert target is not None  # FK + the join in _org_scan
    if get_settings().require_ownership_verification and not target.is_scannable:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Target is not scannable yet — verify ownership first."
        )

    # Same speed / depth / recon profile (and tools) as the scan being retried.
    options = dict(old.options or {})
    used = scan_options.active_tools(options)
    tools: list[str] = []
    confirmation: AuthorisationIn | None = None
    carried_over_from: UUID | None = None
    if used:
        if payload is not None and payload.drop_active_tools:
            for key in scan_options.ACTIVE_TOOL_KEYS:
                options[key] = False
        elif payload is not None and payload.authorisation is not None:
            known = {k: options[k] for k in _RETRY_OPTION_KEYS if k in options}
            request = ScanCreate(triggered_by="retry", authorisation=payload.authorisation, **known)
            tools = _validate_active_tools(request, target, identity)
            options["target_environment"] = _environment(request, target)
            confirmation = payload.authorisation
            carried_over_from = old.id
        else:
            names = ", ".join(scan_options.ACTIVE_TOOL_LABELS[t] for t in used)
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"This scan used active tools ({names}). Retrying needs the "
                "'I'm authorised' confirmation again, or retry without them.",
            )
    return await _start_scan(
        session,
        target,
        triggered_by="retry",
        options=options,
        identity=identity,
        tools=tools,
        confirmation=confirmation,
        carried_over_from=carried_over_from,
    )


async def _set_cancel_flag(scan_id: UUID, who: str) -> None:
    client = aioredis.from_url(get_settings().redis_url)
    try:
        await client.set(f"{CANCEL_KEY_PREFIX}{scan_id}", who, ex=CANCEL_KEY_TTL_S)
    finally:
        await client.aclose()


@router.post(
    "/scans/{scan_id}/cancel", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED
)
async def cancel_scan(
    scan_id: UUID,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
    identity: Identity | None = Depends(get_identity),
) -> Scan:
    """Stop a scan. A scan that has not started (queued, or paused) is closed
    here, at once. A running scan is asked to stop: the worker sees the flag
    within about a second inside a tool and at the next step otherwise, kills
    what it started, and closes the scan as cancelled — so the response is
    202 (accepted), and the scan's state changes a moment later.

    Needs no identity: stopping traffic is a safety action anyone who can open
    the dashboard may take. The name is recorded when there is one."""
    scan = await _org_scan(session, scan_id, org)
    if scan.state in TERMINAL_STATES:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This scan has already finished ({scan.state.value}); there is nothing to cancel.",
        )
    who = identity.username if identity else "unknown"

    if scan.state in (ScanState.QUEUED, ScanState.PAUSED):
        was_queued = scan.state is ScanState.QUEUED
        reason = (
            f"Cancelled by {who} before it started."
            if was_queued
            else f"Cancelled by {who} while paused."
        )
        # Conditional on the state so a worker that picked the scan up a
        # moment ago is not overwritten; then it falls through to the flag.
        closed = await session.execute(
            update(Scan)
            .where(Scan.id == scan.id, Scan.state.in_([ScanState.QUEUED, ScanState.PAUSED]))
            .values(
                state=ScanState.CANCELLED,
                finished_at=datetime.now(UTC),
                fail_reason=reason,
            )
            .returning(Scan.id)
        )
        await session.commit()
        if closed.first() is not None:
            # Also leave the flag, in case a worker had just loaded the scan as queued.
            try:
                await _set_cancel_flag(scan.id, who)
            except Exception:  # noqa: BLE001 — the scan is already closed; the flag is a backstop
                log.warning("scans.cancel_flag_failed", scan_id=str(scan.id), exc_info=True)
            return await _org_scan(session, scan_id, org)

    try:
        await _set_cancel_flag(scan.id, who)
    except Exception as exc:  # noqa: BLE001 — surface it: the scan is NOT being stopped
        log.warning("scans.cancel_flag_failed", scan_id=str(scan.id), exc_info=True)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Could not reach the job queue to send the cancel request. Try again in a moment.",
        ) from exc
    return await _org_scan(session, scan_id, org)


@router.get("/scans/{scan_id}/authorisation", response_model=ScanAuthorisationOut)
async def get_scan_authorisation(
    scan: Scan = Depends(get_owned_scan),
    session: AsyncSession = Depends(get_session),
) -> ScanAuthorisation:
    row = (
        await session.execute(select(ScanAuthorisation).where(ScanAuthorisation.scan_id == scan.id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No authorisation record: this scan used no active tools.",
        )
    return row


@router.get("/targets/{target_id}/scans", response_model=list[ScanOut])
async def list_scans(
    target: Target = Depends(get_owned_target),
    session: AsyncSession = Depends(get_session),
) -> list[Scan]:
    result = await session.execute(
        select(Scan).where(Scan.target_id == target.id).options(selectinload(Scan.phases))
    )
    return list(result.scalars().all())


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: UUID,
    org: Organization = Depends(get_current_org),
    session: AsyncSession = Depends(get_session),
) -> Scan:
    return await _org_scan(session, scan_id, org)


async def _org_scan(session: AsyncSession, scan_id: UUID, org: Organization) -> Scan:
    # Joined through Target so this can never return a scan belonging to
    # another org's target — the exact class of bug this product exists to
    # find (docs/03 §4 — horizontal/IDOR), so it does not get to exist here.
    result = await session.execute(
        select(Scan)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.id == scan_id, Target.organization_id == org.id)
        .options(selectinload(Scan.phases))
        .execution_options(populate_existing=True)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    return scan

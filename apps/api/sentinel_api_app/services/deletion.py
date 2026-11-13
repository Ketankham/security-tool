"""Deleting organizations, targets and personas (QA #40 and the "can't edit
or delete" follow-ups).

The database cascades most of it (organization -> targets -> scans ->
findings/transcripts/assets, and target -> personas), with two gaps this
module closes:

- transcript_records.persona_id points at personas without a cascade, so a
  persona that appears in old scans' transcripts is detached from them
  (set to NULL) before it is deleted: the scan history stays readable;
- credentials are referenced *by* personas, so deleting a persona leaves its
  encrypted secret behind; those rows are deleted explicitly.

Nothing is deleted while one of its scans is still running: the worker
would crash mid-scan writing to rows that are gone.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from fastapi import HTTPException, status
from sentinel_core.state_machine import TERMINAL_STATES, ScanState
from sentinel_db.models import Credential, Persona, Scan, Target, TranscriptRecord
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

_NOT_RUNNING = [*TERMINAL_STATES]


async def refuse_if_scanning(session: AsyncSession, target_ids: Iterable[uuid.UUID]) -> None:
    ids = list(target_ids)
    if not ids:
        return
    running = await session.execute(
        select(Scan.id).where(
            Scan.target_id.in_(ids),
            Scan.state.not_in(_NOT_RUNNING),
            # A scan stuck "Queued" (never picked up) doesn't block deletion.
            Scan.state != ScanState.QUEUED,
        )
    )
    if running.first() is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "A scan is still running here. Wait for it to finish (or fail), then delete.",
        )


async def delete_personas(session: AsyncSession, persona_ids: list[uuid.UUID]) -> None:
    if not persona_ids:
        return
    credential_ids = [
        c
        for c in (
            await session.execute(select(Persona.credential_id).where(Persona.id.in_(persona_ids)))
        ).scalars()
        if c is not None
    ]
    await session.execute(
        update(TranscriptRecord)
        .where(TranscriptRecord.persona_id.in_(persona_ids))
        .values(persona_id=None)
    )
    await session.execute(delete(Persona).where(Persona.id.in_(persona_ids)))
    if credential_ids:
        await session.execute(delete(Credential).where(Credential.id.in_(credential_ids)))


async def delete_targets(session: AsyncSession, target_ids: list[uuid.UUID]) -> None:
    if not target_ids:
        return
    persona_ids = list(
        (await session.execute(select(Persona.id).where(Persona.target_id.in_(target_ids))))
        .scalars()
        .all()
    )
    await delete_personas(session, persona_ids)
    # Core DELETE: the database's ON DELETE CASCADE removes scans and
    # everything under them (the ORM would try to load and null them first).
    await session.execute(delete(Target).where(Target.id.in_(target_ids)))

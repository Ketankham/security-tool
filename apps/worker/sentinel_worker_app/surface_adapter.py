"""Merges sentinel_crawler.SurfaceMap results into Asset/Endpoint DB rows
(docs/01-architecture.md §6, Endpoint.discovered_by_persona_ids). Finds or
creates an Asset per host — reusing the same row Phase 1 recon already
created for that host rather than duplicating it — and finds or creates an
Endpoint per (asset, method, path_template), merging persona IDs into
existing rows so the same endpoint found by two personas is one row, not
two (that merge is what makes the cross-persona diff in docs/00 §3 step 4
a query instead of a re-crawl).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from sentinel_crawler import DiscoveredEndpoint, SurfaceMap
from sentinel_db.models import Asset, Endpoint
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class MergeStats:
    assets_created: int
    endpoints_created: int
    endpoints_merged: int  # already existed, persona_id added to an existing row


async def merge_surface_map(
    session: AsyncSession, *, scan_id: uuid.UUID, surface: SurfaceMap
) -> MergeStats:
    assets_created = 0
    endpoints_created = 0
    endpoints_merged = 0
    asset_cache: dict[str, Asset] = {}

    for endpoint in surface.endpoints:
        host = urlsplit(endpoint.url).hostname or ""
        asset = asset_cache.get(host)
        if asset is None:
            asset, created = await _get_or_create_asset(session, scan_id=scan_id, host=host)
            asset_cache[host] = asset
            assets_created += int(created)

        merged = await _merge_endpoint(session, asset_id=asset.id, discovered=endpoint)
        if merged:
            endpoints_merged += 1
        else:
            endpoints_created += 1

    await session.flush()
    return MergeStats(
        assets_created=assets_created,
        endpoints_created=endpoints_created,
        endpoints_merged=endpoints_merged,
    )


async def _get_or_create_asset(
    session: AsyncSession, *, scan_id: uuid.UUID, host: str
) -> tuple[Asset, bool]:
    result = await session.execute(
        select(Asset).where(Asset.scan_id == scan_id, Asset.host == host)
    )
    asset = result.scalar_one_or_none()
    if asset is not None:
        return asset, False

    asset = Asset(scan_id=scan_id, host=host, discovery_source="crawl")
    session.add(asset)
    await session.flush()
    return asset, True


async def _merge_endpoint(
    session: AsyncSession, *, asset_id: uuid.UUID, discovered: DiscoveredEndpoint
) -> bool:
    """Returns True if an existing row was merged into, False if a new one
    was created."""
    result = await session.execute(
        select(Endpoint).where(
            Endpoint.asset_id == asset_id,
            Endpoint.method == discovered.method,
            Endpoint.path_template == discovered.path_template,
        )
    )
    endpoint = result.scalar_one_or_none()

    if endpoint is None:
        session.add(
            Endpoint(
                asset_id=asset_id,
                method=discovered.method,
                path_template=discovered.path_template,
                discovered_by_persona_ids=[discovered.persona_id],
                discovery_source="js_extraction"
                if discovered.source == "network"
                else "rendered_crawl",
            )
        )
        return False

    if discovered.persona_id not in endpoint.discovered_by_persona_ids:
        endpoint.discovered_by_persona_ids = [
            *endpoint.discovered_by_persona_ids,
            discovered.persona_id,
        ]
    return True

"""Smoke test only — see README.md. This does NOT measure detection rate
or false positives; it exists so `docker compose -f
tests/benchmark/docker-compose.yml up -d` has *something* to verify before
the real scoring harness lands in M2.

Note: this deliberately does not route through `sentinel_recon.run_recon`.
Recon (packages/recon) targets internet-facing domains on standard ports —
DNS resolution plus :80/:443 probing — and has no notion of an arbitrary
docker-compose port mapping like Juice Shop's :3000. Bridging that (so the
real scanner can be pointed at a fixture during development) is itself a
gap worth tracking, not something to paper over with a misleading test.
"""

from __future__ import annotations

import httpx
import pytest

JUICE_SHOP_URL = "http://localhost:3000/"


async def test_juice_shop_fixture_is_reachable():
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(JUICE_SHOP_URL)
    except httpx.HTTPError:
        pytest.skip(
            f"Juice Shop not reachable at {JUICE_SHOP_URL} — run "
            "`docker compose -f tests/benchmark/docker-compose.yml up -d` first."
        )
        return

    if resp.status_code >= 500:
        pytest.skip(f"Juice Shop at {JUICE_SHOP_URL} returned {resp.status_code} — not ready yet.")

    assert resp.status_code == 200
    assert "juice" in resp.text.lower() or "OWASP" in resp.text

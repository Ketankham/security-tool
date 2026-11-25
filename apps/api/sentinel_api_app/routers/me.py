"""Who am I, what can I do here, and what would a scan cost.

Neither route needs X-Org-Id: ``/whoami`` is how the dashboard learns who is
signed in and which active tools this build offers (it hides the tool
checkboxes for any tool not listed in ``available_tools``), and
``/scan-estimate`` is pure arithmetic over the scan options.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sentinel_core import authorisation, scan_options

from ..identity import Identity, get_identity

router = APIRouter(tags=["me"])


@router.get("/whoami")
async def whoami(identity: Identity | None = Depends(get_identity)) -> dict:
    return {
        "username": identity.username if identity else None,
        "source": identity.source if identity else None,
        "available_tools": list(scan_options.IMPLEMENTED_ACTIVE_TOOLS),
        "statement": {
            "version": authorisation.STATEMENT_VERSION,
            "template": authorisation.STATEMENT_TEMPLATE,
            "all_ports_template": authorisation.ALL_PORTS_STATEMENT,
        },
    }


@router.get("/scan-estimate")
async def scan_estimate(
    speed: scan_options.Speed = scan_options.DEFAULT_SPEED,
    depth: scan_options.Depth = scan_options.DEFAULT_DEPTH,
    recon_profile: scan_options.ReconProfile = scan_options.DEFAULT_RECON_PROFILE,
    dir_bruteforce: bool = Query(default=False),
    port_scan: bool = Query(default=False),
    all_ports: bool = Query(default=False),
    wordlist: scan_options.Wordlist = scan_options.DEFAULT_WORDLIST,
) -> dict:
    """Worst-case time the chosen active tools could take (see
    sentinel_core.scan_options.estimate). Stateless: nothing is stored."""
    return scan_options.estimate(
        {
            "speed": speed,
            "depth": depth,
            "recon_profile": recon_profile,
            "dir_bruteforce": dir_bruteforce,
            "port_scan": port_scan,
            "all_ports": all_ports,
            "wordlist": wordlist,
        }
    )

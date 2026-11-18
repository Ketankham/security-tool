"""CORS misconfiguration (docs/03 §2).

A request carrying a made-up ``Origin`` is sent to the site's pages and to
the background (XHR/fetch) endpoints the crawl saw. A server that echoes that
origin back in ``Access-Control-Allow-Origin`` lets any website read its
responses from a visitor's browser; with ``Access-Control-Allow-Credentials:
true`` it can do so *as the logged-in visitor*, which is the serious case.
Requests are anonymous, so nothing private is read.
"""

from __future__ import annotations

from .models import EvidenceRef, PassiveCandidate, PassiveContext, curl_for, hget

_PROBE_ORIGINS = ("https://sentinel-probe.example", "null")


def reflected(headers: dict[str, str], origin: str) -> tuple[bool, bool]:
    """(the origin is allowed, credentials are allowed)."""
    allow = (hget(headers, "access-control-allow-origin") or "").strip()
    creds = (hget(headers, "access-control-allow-credentials") or "").strip().lower() == "true"
    return allow == origin, creds


async def check_cors(ctx: PassiveContext) -> list[PassiveCandidate]:
    candidates: list[PassiveCandidate] = []
    probed = 0
    for origin in ctx.origins:
        if origin in ctx.unreachable:
            continue
        api_urls = ctx.api_urls_by_origin.get(origin, [])[:6]
        root = (ctx.pages_by_origin.get(origin) or [f"{origin}/"])[0]
        # (url, probe origin, credentials?, is an API endpoint?, evidence)
        hits: list[tuple[str, str, bool, bool, EvidenceRef]] = []
        for url in [root, *api_urls]:
            for probe in _PROBE_ORIGINS:
                response = await ctx.fetch("GET", url, headers={"Origin": probe})
                if response is None:
                    continue
                probed += 1
                allowed, creds = reflected(response.headers, probe)
                is_api = url != root
                if allowed and (creds or is_api):
                    hits.append(
                        (
                            url,
                            probe,
                            creds,
                            is_api,
                            EvidenceRef(
                                transcript_id=response.transcript_id,
                                method="GET",
                                url=url,
                                status_code=response.status_code,
                                role="cors-response",
                                note=f"Sent Origin: {probe}; got Access-Control-Allow-Origin: "
                                f"{hget(response.headers, 'access-control-allow-origin')}"
                                f"{', Allow-Credentials: true' if creds else ''}",
                            ),
                        )
                    )
        for with_creds in (True, False):
            group = [h for h in hits if h[2] is with_creds]
            if not group:
                continue
            url, probe, _, _, evidence = group[0]
            urls = sorted({h[0] for h in group})

            def make_reproduce(url: str = url, probe: str = probe, with_creds: bool = with_creds):
                async def reproduce() -> bool:
                    again = await ctx.fetch("GET", url, headers={"Origin": probe})
                    if again is None:
                        return False
                    allowed, creds = reflected(again.headers, probe)
                    return allowed and (creds if with_creds else True)

                return reproduce

            candidates.append(
                PassiveCandidate(
                    rule_id="cors.reflected_origin_credentials"
                    if with_creds
                    else "cors.reflected_origin",
                    title=(
                        f"CORS allows any website to read responses as the logged-in user "
                        f"({origin.split('://', 1)[1]})"
                        if with_creds
                        else "CORS reflects any Origin on API endpoints "
                        f"({origin.split('://', 1)[1]})"
                    ),
                    severity="high" if with_creds else "low",
                    cwe=[942],
                    owasp="A05:2021",
                    origin=origin,
                    subject="credentials" if with_creds else "api",
                    narrative=(
                        "The server copies whatever Origin it is sent into Access-Control-Allow-"
                        "Origin"
                        + (
                            " and also sends Access-Control-Allow-Credentials: true. Any website "
                            "a logged-in user visits can therefore make their browser call this "
                            "server and read the answer, including private data."
                            if with_creds
                            else ", so any website can read these responses from a visitor's "
                            "browser. No credentials are allowed, so only public data is "
                            "exposed, but it is not what an allow-list should look like."
                        )
                        + f" Affected: {', '.join(urls[:5])}. Probe origin used: {probe}."
                    ),
                    remediation_summary="Allow only a fixed list of trusted origins; never echo "
                    "the request's Origin, and never combine a reflected origin with credentials.",
                    remediation_steps=[
                        "Replace the 'echo the Origin header' logic with an exact allow-list "
                        "of your own front-end origins.",
                        "Only send Access-Control-Allow-Credentials: true to origins on that list.",
                        "Never allow the 'null' origin.",
                    ],
                    reproduction_curl=curl_for(url, headers={"Origin": probe}),
                    reproduction_expect=(
                        f"The response contains Access-Control-Allow-Origin: {probe}"
                        + (" and Access-Control-Allow-Credentials: true." if with_creds else ".")
                    ),
                    evidence=[evidence],
                    reproduce=make_reproduce(),
                )
            )
    ctx.log(
        "info",
        f"CORS check: {probed} probe request(s) sent, {len(candidates)} issue(s) found.",
    )
    return candidates

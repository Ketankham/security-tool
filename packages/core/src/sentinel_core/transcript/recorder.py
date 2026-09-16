"""TranscriptRecorder: the shared choke point that writes every
request/response pair to evidence storage (docs/01-architecture.md §4.1
item 4).

Usage: the HTTP engine calls ``record()`` after every request completes
(success, HTTP error, or transport failure). The recorder scrubs secrets,
serialises to JSON, stores it via the configured TranscriptStore, and
returns the transcript_id for the caller to attach to any Finding/Evidence.
"""

from __future__ import annotations

import json

from .models import RecordedRequest, RecordedResponse, Transcript
from .scrub import scrub_body, scrub_headers
from .store import TranscriptStore


class TranscriptRecorder:
    def __init__(self, store: TranscriptStore, *, known_secrets: list[str] | None = None) -> None:
        self._store = store
        self._known_secrets = known_secrets or []

    async def record(
        self,
        *,
        scan_id: str,
        persona_id: str | None,
        request: RecordedRequest,
        response: RecordedResponse | None,
        error: str | None = None,
    ) -> str:
        scrubbed_request = RecordedRequest(
            method=request.method,
            url=request.url,
            headers=scrub_headers(request.headers),
            body=scrub_body(request.body, known_secrets=self._known_secrets),
        )
        scrubbed_response = None
        if response is not None:
            scrubbed_response = RecordedResponse(
                status_code=response.status_code,
                headers=scrub_headers(response.headers),
                body=scrub_body(response.body, known_secrets=self._known_secrets),
                elapsed_ms=response.elapsed_ms,
            )

        transcript = Transcript(
            scan_id=scan_id,
            persona_id=persona_id,
            request=scrubbed_request,
            response=scrubbed_response,
            error=error,
        )
        payload = _serialise(transcript)
        return await self._store.put(payload, content_type="application/json")

    async def load(self, transcript_id: str) -> dict:
        raw = await self._store.get(transcript_id)
        return json.loads(raw)


def _serialise(transcript: Transcript) -> bytes:
    def _body(b: bytes | None) -> str | None:
        if b is None:
            return None
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            import base64  # noqa: PLC0415

            return "base64:" + base64.b64encode(b).decode("ascii")

    doc = {
        "scan_id": transcript.scan_id,
        "persona_id": transcript.persona_id,
        "recorded_at": transcript.recorded_at.isoformat(),
        "error": transcript.error,
        "request": {
            "method": transcript.request.method,
            "url": transcript.request.url,
            "headers": transcript.request.headers,
            "body": _body(transcript.request.body),
        },
        "response": (
            {
                "status_code": transcript.response.status_code,
                "headers": transcript.response.headers,
                "body": _body(transcript.response.body),
                "elapsed_ms": transcript.response.elapsed_ms,
            }
            if transcript.response
            else None
        ),
    }
    return json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")

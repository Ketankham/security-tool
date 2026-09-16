import json

import pytest
from sentinel_core.transcript import (
    LocalTranscriptStore,
    RecordedRequest,
    RecordedResponse,
    TranscriptRecorder,
)
from sentinel_core.transcript.scrub import scrub_body, scrub_headers


def test_scrub_headers_redacts_sensitive_names():
    headers = {
        "Authorization": "Bearer abc123",
        "Cookie": "sid=xyz",
        "Content-Type": "application/json",
    }
    scrubbed = scrub_headers(headers)
    assert scrubbed["Authorization"] == "«redacted»"
    assert scrubbed["Cookie"] == "«redacted»"
    assert scrubbed["Content-Type"] == "application/json"


def test_scrub_body_redacts_known_secret_value():
    body = b'{"token": "s3cr3t-value", "name": "ok"}'
    scrubbed = scrub_body(body, known_secrets=["s3cr3t-value"])
    assert b"s3cr3t-value" not in scrubbed
    assert b"ok" in scrubbed


def test_scrub_body_redacts_jwt_pattern():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dGhpc2lzbm90YXJlYWxzaWc"
    body = f'{{"session": "{jwt}"}}'.encode()
    scrubbed = scrub_body(body)
    assert jwt.encode() not in scrubbed


def test_scrub_body_leaves_binary_alone():
    binary = b"\xff\xd8\xff\xe0not-utf8\x00\x01"
    assert scrub_body(binary) == binary


async def test_local_store_roundtrip(tmp_path):
    store = LocalTranscriptStore(tmp_path)
    content = b'{"hello": "world"}'
    tid = await store.put(content)
    assert await store.get(tid) == content


async def test_local_store_is_content_addressed(tmp_path):
    store = LocalTranscriptStore(tmp_path)
    id1 = await store.put(b"same content")
    id2 = await store.put(b"same content")
    assert id1 == id2


async def test_local_store_missing_id_raises(tmp_path):
    store = LocalTranscriptStore(tmp_path)
    with pytest.raises(FileNotFoundError):
        await store.get("0" * 64)


async def test_recorder_scrubs_and_persists_transcript(tmp_path):
    store = LocalTranscriptStore(tmp_path)
    recorder = TranscriptRecorder(store, known_secrets=["super-secret-password"])

    req = RecordedRequest(
        method="POST",
        url="https://app.acme.test/login",
        headers={
            "Authorization": "Bearer super-secret-password",
            "Content-Type": "application/json",
        },
        body=b'{"password": "super-secret-password"}',
    )
    resp = RecordedResponse(
        status_code=200, headers={"Set-Cookie": "sid=abc"}, body=b'{"ok": true}'
    )

    tid = await recorder.record(
        scan_id="scan-1", persona_id="persona-admin", request=req, response=resp
    )
    stored = await recorder.load(tid)

    assert stored["request"]["headers"]["Authorization"] == "«redacted»"
    assert "super-secret-password" not in json.dumps(stored)
    assert stored["response"]["headers"]["Set-Cookie"] == "«redacted»"
    assert stored["response"]["body"] == '{"ok": true}'
    assert stored["scan_id"] == "scan-1"
    assert stored["persona_id"] == "persona-admin"

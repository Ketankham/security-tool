"""Storage backends for transcripts (docs/01-architecture.md §3.1).

Content-addressed: the key is derived from the content hash, so writes are
idempotent and evidence can never be silently mutated after the fact. Local
disk for dev/CI; an S3-compatible backend (Cloudflare R2 in production, or
any S3 API) for real deployments.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path


class TranscriptStore(ABC):
    @abstractmethod
    async def put(self, content: bytes, *, content_type: str = "application/json") -> str:
        """Store content, return a stable transcript_id (its content hash)."""

    @abstractmethod
    async def get(self, transcript_id: str) -> bytes:
        """Retrieve previously stored content by its transcript_id."""

    @staticmethod
    def content_id(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()


class LocalTranscriptStore(TranscriptStore):
    """Dev/CI backend: content-addressed files under a local directory."""

    def __init__(self, base_path: str | Path) -> None:
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _path_for(self, transcript_id: str) -> Path:
        # Shard by the first two hex chars to avoid one giant flat directory.
        return self.base_path / transcript_id[:2] / f"{transcript_id}.bin"

    async def put(self, content: bytes, *, content_type: str = "application/json") -> str:
        transcript_id = self.content_id(content)
        path = self._path_for(transcript_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():  # content-addressed => already-written is already correct
            path.write_bytes(content)
        return transcript_id

    async def get(self, transcript_id: str) -> bytes:
        path = self._path_for(transcript_id)
        if not path.exists():
            raise FileNotFoundError(f"No transcript stored for id {transcript_id}")
        return path.read_bytes()


class S3TranscriptStore(TranscriptStore):
    """Production backend: any S3-compatible API (Cloudflare R2, AWS S3, MinIO).

    boto3 is an optional dependency (``pip install sentinel-core[s3]``) so the
    dev/CI path never needs it.
    """

    def __init__(
        self,
        *,
        bucket: str,
        endpoint_url: str | None = None,
        region_name: str = "auto",
        prefix: str = "transcripts",
    ) -> None:
        try:
            import boto3  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "S3TranscriptStore requires boto3. Install with `pip install sentinel-core[s3]`."
            ) from exc

        self._bucket = bucket
        self._prefix = prefix.rstrip("/")
        self._client = boto3.client("s3", endpoint_url=endpoint_url, region_name=region_name)

    def _key_for(self, transcript_id: str) -> str:
        return f"{self._prefix}/{transcript_id[:2]}/{transcript_id}.bin"

    async def put(self, content: bytes, *, content_type: str = "application/json") -> str:
        import asyncio  # noqa: PLC0415

        transcript_id = self.content_id(content)
        key = self._key_for(transcript_id)

        def _upload() -> None:
            self._client.put_object(
                Bucket=self._bucket, Key=key, Body=content, ContentType=content_type
            )

        await asyncio.to_thread(_upload)
        return transcript_id

    async def get(self, transcript_id: str) -> bytes:
        import asyncio  # noqa: PLC0415

        key = self._key_for(transcript_id)

        def _download() -> bytes:
            obj = self._client.get_object(Bucket=self._bucket, Key=key)
            return obj["Body"].read()

        return await asyncio.to_thread(_download)

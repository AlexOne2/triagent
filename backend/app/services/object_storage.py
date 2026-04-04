from __future__ import annotations

import hashlib
import io
from pathlib import PurePosixPath
import re
from urllib.parse import urlparse

from minio import Minio

from app.core.config import Settings, get_settings


class ObjectStorageError(RuntimeError):
    pass


def _build_minio_client(settings: Settings) -> Minio:
    parsed = urlparse(settings.minio_endpoint)
    host = parsed.netloc or parsed.path
    secure = parsed.scheme == "https"
    if not host:
        raise ObjectStorageError("Invalid MINIO_ENDPOINT")
    return Minio(
        host,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=secure,
    )


_FILENAME_SANITIZER = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(filename: str | None) -> str:
    if not filename:
        return "attachment.bin"
    cleaned = filename.strip().replace("\\", "/").split("/")[-1]
    cleaned = _FILENAME_SANITIZER.sub("_", cleaned)
    cleaned = cleaned.strip("._")
    if not cleaned:
        return "attachment.bin"
    return cleaned[:180]


class ObjectStorageService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.client = _build_minio_client(self.settings)
        self.bucket = self.settings.minio_bucket
        self._bucket_ready = False

    def _ensure_bucket(self) -> None:
        if self._bucket_ready:
            return
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
        except Exception as exc:
            raise ObjectStorageError("Attachment storage is unavailable") from exc
        self._bucket_ready = True

    def put_attachment(
        self,
        *,
        report_id: int,
        filename: str | None,
        content_type: str | None,
        data: bytes,
    ) -> dict[str, str | int]:
        self._ensure_bucket()
        sha256 = hashlib.sha256(data).hexdigest()
        safe_name = sanitize_filename(filename)
        object_name = str(
            PurePosixPath(
                "reports",
                str(report_id),
                "attachments",
                f"{sha256[:12]}-{safe_name}",
            )
        )
        data_stream = io.BytesIO(data)
        try:
            self.client.put_object(
                bucket_name=self.bucket,
                object_name=object_name,
                data=data_stream,
                length=len(data),
                content_type=content_type or "application/octet-stream",
            )
        except Exception as exc:
            raise ObjectStorageError("Attachment storage is unavailable") from exc
        return {
            "s3_key": object_name,
            "sha256": sha256,
            "size_bytes": len(data),
        }

    def delete_attachment(self, object_name: str | None) -> None:
        if not object_name:
            return
        self._ensure_bucket()
        try:
            self.client.remove_object(self.bucket, object_name)
        except Exception as exc:
            raise ObjectStorageError("Attachment storage is unavailable") from exc

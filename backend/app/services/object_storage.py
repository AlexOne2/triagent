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
_CONTROL_CHAR_SANITIZER = re.compile(r"[\x00-\x1f\x7f]+")


def normalize_filename(filename: str | None, *, default: str) -> str:
    if not filename:
        return default
    cleaned = filename.strip().replace("\\", "/").split("/")[-1]
    cleaned = _CONTROL_CHAR_SANITIZER.sub(" ", cleaned).strip()
    if not cleaned:
        return default
    return cleaned[:255]


def sanitize_filename(filename: str | None, *, default: str = "attachment.bin") -> str:
    cleaned = normalize_filename(filename, default=default)
    cleaned = _FILENAME_SANITIZER.sub("_", cleaned)
    cleaned = cleaned.strip("._")
    if not cleaned:
        return default
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
            raise ObjectStorageError("Artifact storage is unavailable") from exc
        self._bucket_ready = True

    def _put_report_object(
        self,
        *,
        report_id: int,
        folder: str,
        filename: str | None,
        content_type: str | None,
        data: bytes,
        default_filename: str,
    ) -> dict[str, str | int]:
        self._ensure_bucket()
        sha256 = hashlib.sha256(data).hexdigest()
        normalized_filename = normalize_filename(filename, default=default_filename)
        safe_name = sanitize_filename(normalized_filename, default=default_filename)
        object_name = str(
            PurePosixPath(
                "reports",
                str(report_id),
                folder,
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
            raise ObjectStorageError("Artifact storage is unavailable") from exc
        return {
            "filename": normalized_filename,
            "content_type": content_type or "application/octet-stream",
            "s3_key": object_name,
            "sha256": sha256,
            "size_bytes": len(data),
        }

    def put_attachment(
        self,
        *,
        report_id: int,
        filename: str | None,
        content_type: str | None,
        data: bytes,
    ) -> dict[str, str | int]:
        return self._put_report_object(
            report_id=report_id,
            folder="attachments",
            filename=filename,
            content_type=content_type,
            data=data,
            default_filename="attachment.bin",
        )

    def put_original_message(
        self,
        *,
        report_id: int,
        filename: str | None,
        content_type: str | None,
        data: bytes,
    ) -> dict[str, str | int]:
        return self._put_report_object(
            report_id=report_id,
            folder="original-message",
            filename=filename,
            content_type=content_type,
            data=data,
            default_filename="original-message.bin",
        )

    def delete_attachment(self, object_name: str | None) -> None:
        if not object_name:
            return
        self._ensure_bucket()
        try:
            self.client.remove_object(self.bucket, object_name)
        except Exception as exc:
            raise ObjectStorageError("Artifact storage is unavailable") from exc

    def delete_original_message(self, object_name: str | None) -> None:
        if not object_name:
            return
        self._ensure_bucket()
        try:
            self.client.remove_object(self.bucket, object_name)
        except Exception as exc:
            raise ObjectStorageError("Artifact storage is unavailable") from exc

    def get_attachment(self, object_name: str | None) -> bytes:
        if not object_name:
            raise ObjectStorageError("Attachment is unavailable")
        self._ensure_bucket()
        response = None
        try:
            response = self.client.get_object(self.bucket, object_name)
            return response.read()
        except Exception as exc:
            raise ObjectStorageError("Artifact storage is unavailable") from exc
        finally:
            if response is not None:
                response.close()
                response.release_conn()

    def get_original_message(self, object_name: str | None) -> bytes:
        if not object_name:
            raise ObjectStorageError("Original message is unavailable")
        self._ensure_bucket()
        response = None
        try:
            response = self.client.get_object(self.bucket, object_name)
            return response.read()
        except Exception as exc:
            raise ObjectStorageError("Artifact storage is unavailable") from exc
        finally:
            if response is not None:
                response.close()
                response.release_conn()

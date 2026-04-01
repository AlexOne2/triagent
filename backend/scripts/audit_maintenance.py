from __future__ import annotations

import argparse
import io
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import sqlalchemy as sa
from minio import Minio

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.security_audit import AuditActorType, AuditExport, SecurityAuditEvent
from app.services.audit import AuditService, utcnow
from app.services.auth import create_security_audit_event


def _parse_iso(value: str) -> datetime:
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _build_minio_client(endpoint: str, access_key: str, secret_key: str) -> Minio:
    parsed = urlparse(endpoint)
    host = parsed.netloc or parsed.path
    secure = parsed.scheme == "https"
    return Minio(host, access_key=access_key, secret_key=secret_key, secure=secure)


def _export_to_minio(
    *,
    settings,
    file_stem: str,
    lines: list[str],
    manifest: dict,
) -> str:
    client = _build_minio_client(
        endpoint=settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
    )
    bucket = settings.audit_export_bucket
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)

    ndjson_content = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    manifest_content = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")

    ndjson_key = f"{file_stem}.ndjson"
    manifest_key = f"{file_stem}.manifest.json"

    client.put_object(
        bucket_name=bucket,
        object_name=ndjson_key,
        data=io.BytesIO(ndjson_content),
        length=len(ndjson_content),
        content_type="application/x-ndjson",
    )
    client.put_object(
        bucket_name=bucket,
        object_name=manifest_key,
        data=io.BytesIO(manifest_content),
        length=len(manifest_content),
        content_type="application/json",
    )
    return f"minio://{bucket}/{ndjson_key}"


def cmd_verify(args) -> int:
    db = SessionLocal()
    try:
        service = AuditService(db)
        start = _parse_iso(args.start) if args.start else None
        end = _parse_iso(args.end) if args.end else None
        result = service.verify_chain(start=start, end=end)
        create_security_audit_event(
            db,
            action="AUDIT_VERIFY_RUN",
            outcome="SUCCESS" if result["valid"] else "FAILURE",
            target_type="audit_range",
            target_id=f"{result.get('range_start')}..{result.get('range_end')}",
            metadata={"checked_count": result["checked_count"], "script": True},
            actor_type=AuditActorType.SYSTEM,
        )
        db.commit()
        print(json.dumps(result, indent=2))
        return 0 if result["valid"] else 2
    finally:
        db.close()


def cmd_export(args) -> int:
    settings = get_settings()
    if not settings.audit_export_enabled:
        raise RuntimeError("AUDIT_EXPORT_ENABLED is false")

    start = _parse_iso(args.start)
    end = _parse_iso(args.end)
    if start > end:
        raise ValueError("start must be before end")

    db = SessionLocal()
    try:
        service = AuditService(db, settings=settings)
        lines, manifest = service.ndjson_for_range(start=start, end=end)
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        file_stem = f"audit-{start.date().isoformat()}-{end.date().isoformat()}-{stamp}"

        storage = settings.audit_export_storage.strip().lower()
        if storage == "minio":
            storage_uri = _export_to_minio(settings=settings, file_stem=file_stem, lines=lines, manifest=manifest)
        else:
            storage_uri = service.write_export_to_filesystem(
                base_path=settings.audit_export_path,
                file_stem=file_stem,
                lines=lines,
                manifest=manifest,
            )

        export = service.record_export(
            range_start=start,
            range_end=end,
            event_count=int(manifest["event_count"]),
            root_hash=str(manifest["root_hash"]),
            manifest_json=manifest,
            storage_uri=storage_uri,
            created_by=args.created_by,
        )
        create_security_audit_event(
            db,
            action="AUDIT_EXPORT_RUN",
            outcome="SUCCESS",
            target_type="audit_export",
            target_id=str(export.id),
            metadata={
                "range_start": manifest["range_start"],
                "range_end": manifest["range_end"],
                "event_count": manifest["event_count"],
                "root_hash": manifest["root_hash"],
                "storage_uri": storage_uri,
                "script": True,
            },
            actor_type=AuditActorType.SYSTEM,
        )
        db.commit()
        print(
            json.dumps(
                {
                    "export_id": export.id,
                    "event_count": export.event_count,
                    "root_hash": export.root_hash,
                    "storage_uri": export.storage_uri,
                },
                indent=2,
            )
        )
        return 0
    finally:
        db.close()


def cmd_prune(_args) -> int:
    settings = get_settings()
    db = SessionLocal()
    try:
        cutoff = utcnow() - timedelta(days=settings.audit_retention_days)
        latest_export_end = db.execute(sa.select(sa.func.max(AuditExport.range_end))).scalar_one_or_none()
        if latest_export_end is None:
            raise RuntimeError("No audit exports found; prune is not allowed")

        eligible_end = min(cutoff, latest_export_end)
        if eligible_end <= datetime(1970, 1, 1, tzinfo=timezone.utc):
            print(json.dumps({"deleted_count": 0, "reason": "eligible range is empty"}, indent=2))
            return 0

        db.execute(sa.text("SET LOCAL app.audit_prune = 'on'"))
        delete_stmt = sa.delete(SecurityAuditEvent).where(SecurityAuditEvent.created_at < eligible_end)
        deleted_count = db.execute(delete_stmt).rowcount or 0

        create_security_audit_event(
            db,
            action="AUDIT_PRUNE_RUN",
            outcome="SUCCESS",
            target_type="audit_range",
            target_id=f"..{eligible_end.isoformat()}",
            metadata={
                "deleted_count": deleted_count,
                "cutoff": cutoff.isoformat(),
                "latest_export_end": latest_export_end.isoformat(),
                "script": True,
            },
            actor_type=AuditActorType.SYSTEM,
        )
        db.commit()
        print(json.dumps({"deleted_count": deleted_count, "eligible_end": eligible_end.isoformat()}, indent=2))
        return 0
    finally:
        db.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit trail maintenance operations")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="Verify tamper-evident audit chain")
    verify_parser.add_argument("--start", type=str, default=None, help="Optional ISO start datetime")
    verify_parser.add_argument("--end", type=str, default=None, help="Optional ISO end datetime")
    verify_parser.set_defaults(handler=cmd_verify)

    export_parser = subparsers.add_parser("export", help="Export audit events to NDJSON and record manifest")
    export_parser.add_argument("--start", type=str, required=True, help="ISO start datetime")
    export_parser.add_argument("--end", type=str, required=True, help="ISO end datetime")
    export_parser.add_argument("--created-by", type=str, default="system-script", help="Creator identity label")
    export_parser.set_defaults(handler=cmd_export)

    prune_parser = subparsers.add_parser("prune", help="Prune exported audit rows older than retention policy")
    prune_parser.set_defaults(handler=cmd_prune)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())

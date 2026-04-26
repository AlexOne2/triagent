from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, selectinload

from app.api.routes import (
    _create_report,
    _original_message_content_type,
    _store_original_message,
    _store_report_attachments,
)
from app.core.config import Settings
from app.models.auth_session import AuthSession
from app.models.report import IngestSource, Report, ReportStatus, ResolutionDisposition
from app.models.report_resolution import ReportResolution, ResolutionAction
from app.models.security_audit import AuditActorType
from app.models.user import User
from app.schemas import ReportCreate
from app.services.analysis import extract_urls
from app.services.auth import AUTH_SOURCE_DEMO, create_security_audit_event, hash_password, replace_user_roles
from app.services.eml_parser import parse_eml
from app.services.msg_parser import parse_msg
from app.services.object_storage import ObjectStorageError, ObjectStorageService
from app.services.rbac import user_role_keys
from app.services.url_resolution import build_url_analysis

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DEMO_CORPUS_ROOT = REPO_ROOT / "test_data" / "synthetic-corpus"
DEFAULT_DEMO_OPEN_SAMPLE_IDS = {
    "benign_vendor_portal_notice_001",
    "display_name_bec_replyto_001",
    "cred_harvest_shortener_001",
}
SHARED_DEMO_USERNAME = "demo_public"
DEMO_PROVISION_LOCK_KEY = 420042
DEMO_SEED_ACTOR = "demo-seed"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _build_fixture_fetcher(fixtures: dict[str, list[dict[str, Any]]]):
    by_url: dict[str, dict[str, Any]] = {}
    for chain in fixtures.values():
        for step in chain:
            by_url[step["url"]] = {
                "status_code": step["status_code"],
                "location": step.get("location"),
            }

    def fetch(url: str) -> dict[str, Any]:
        if url not in by_url:
            raise RuntimeError(f"Missing redirect fixture for {url}")
        return dict(by_url[url])

    return fetch


def _parse_sample(raw_bytes: bytes, message_format: str) -> tuple[dict[str, Any], list[object]]:
    normalized = message_format.lower()
    if normalized == "eml":
        return parse_eml(raw_bytes)
    if normalized == "msg":
        return parse_msg(raw_bytes)
    raise ValueError(f"Unsupported message format: {message_format}")


def _report_status_for_disposition(disposition: str | None) -> ReportStatus:
    if (disposition or "").upper() == "SAFE":
        return ReportStatus.BENIGN
    if (disposition or "").upper() == "MALICIOUS":
        return ReportStatus.PHISHING
    return ReportStatus.OPEN


def _report_resolution_disposition(disposition: str | None) -> ResolutionDisposition | None:
    if (disposition or "").upper() == "SAFE":
        return ResolutionDisposition.SAFE
    if (disposition or "").upper() == "MALICIOUS":
        return ResolutionDisposition.MALICIOUS
    return None


def _apply_seed_resolution(
    db: Session,
    report: Report,
    *,
    disposition: str | None,
    classification_code: str | None,
    note: str,
) -> None:
    resolved_disposition = _report_resolution_disposition(disposition)
    if resolved_disposition is None:
        return

    resolved_at = datetime.now(timezone.utc)
    next_status = _report_status_for_disposition(disposition)
    report.status = next_status
    report.classification_code = classification_code
    report.resolution_note = note
    report.flagged_artifacts_json = None
    report.resolved_at = resolved_at
    report.last_resolved_by = DEMO_SEED_ACTOR

    db.add(
        ReportResolution(
            report_id=report.id,
            action=ResolutionAction.RESOLVE,
            disposition=resolved_disposition,
            status_after=next_status,
            classification_code=classification_code,
            note=note,
            flagged_artifacts_json=None,
            actor=DEMO_SEED_ACTOR,
            actor_user_id=None,
            actor_api_key_id=None,
        )
    )


def _seed_demo_reports(
    *,
    db: Session,
    settings: Settings,
    storage: ObjectStorageService,
    user: User,
) -> int:
    corpus_root = DEFAULT_DEMO_CORPUS_ROOT
    manifest = _load_json(corpus_root / "manifest.json")
    split_payload = _load_json(corpus_root / "splits" / f"{settings.auth_demo_split}.json")
    redirect_fixtures = _load_json(corpus_root / "redirect-fixtures.json").get("fixtures", {})
    fixture_fetcher = _build_fixture_fetcher(redirect_fixtures)
    samples_by_id = {item["sample_id"]: item for item in manifest["samples"]}

    imported = 0
    for sample_id in split_payload["sample_ids"]:
        entry = samples_by_id[sample_id]
        raw_bytes = (corpus_root / entry["relative_path"]).read_bytes()
        parsed_report, parsed_attachments = _parse_sample(raw_bytes, entry["message_format"])

        payload_data = dict(parsed_report)
        payload_data["mailbox_domain"] = entry.get("mailbox_domain")
        urls = extract_urls(parsed_report.get("body_text"), parsed_report.get("body_html"))
        payload_data["url_analysis_json"] = build_url_analysis(
            urls,
            settings=settings,
            resolve_urls=True,
            fetcher=fixture_fetcher,
        )
        payload = ReportCreate(**payload_data)

        report, risk_score = _create_report(
            payload,
            db,
            IngestSource.UPLOAD,
            attachment_names=[item.filename for item in parsed_attachments if item.filename],
            demo_user_id=user.id,
        )

        _store_original_message(
            report=report,
            raw_bytes=raw_bytes,
            filename=entry["file_name"],
            content_type=_original_message_content_type(entry["file_name"], None, file_type=entry["message_format"]),
            file_type=entry["message_format"],
            storage=storage,
        )
        _store_report_attachments(
            db=db,
            report_id=report.id,
            parsed_attachments=parsed_attachments,
            storage=storage,
        )

        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "source": "demo_workspace",
                "sample_id": sample_id,
                "risk_score": risk_score,
                "attachment_count": len(parsed_attachments),
            },
            actor_type=AuditActorType.SYSTEM,
        )

        if sample_id not in DEFAULT_DEMO_OPEN_SAMPLE_IDS:
            _apply_seed_resolution(
                db,
                report,
                disposition=entry.get("disposition"),
                classification_code=entry.get("classification_code"),
                note=f"Demo workspace seed: {sample_id}",
            )
            create_security_audit_event(
                db,
                action="REPORT_RESOLVED",
                outcome="SUCCESS",
                target_type="report",
                target_id=str(report.id),
                metadata={
                    "source": "demo_workspace",
                    "sample_id": sample_id,
                    "status_after": report.status.value,
                    "classification_code": report.classification_code,
                },
                actor_type=AuditActorType.SYSTEM,
            )

        imported += 1

    return imported


def _cleanup_demo_user(db: Session, storage: ObjectStorageService, user: User) -> None:
    reports = (
        db.execute(
            select(Report)
            .where(Report.demo_user_id == user.id)
            .options(selectinload(Report.attachments))
        )
        .scalars()
        .all()
    )
    for report in reports:
        for attachment in report.attachments:
            if attachment.s3_key:
                storage.delete_attachment(attachment.s3_key)
        if report.original_s3_key:
            storage.delete_original_message(report.original_s3_key)
    db.delete(user)


def cleanup_stale_demo_users(db: Session, settings: Settings) -> int:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=settings.auth_demo_retention_hours)
    active_session_exists = (
        select(AuthSession.id)
        .where(
            AuthSession.user_id == User.id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
        .exists()
    )

    stale_users = (
        db.execute(
            select(User)
            .where(
                User.auth_source == AUTH_SOURCE_DEMO,
                User.username != SHARED_DEMO_USERNAME,
                User.created_at < cutoff,
                ~active_session_exists,
            )
            .order_by(User.created_at.asc())
        )
        .scalars()
        .all()
    )
    if not stale_users:
        return 0

    storage = ObjectStorageService(settings)
    for user in stale_users:
        _cleanup_demo_user(db, storage, user)
    return len(stale_users)


def _acquire_demo_provision_lock(db: Session) -> None:
    bind = db.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": DEMO_PROVISION_LOCK_KEY})


def ensure_shared_demo_workspace(db: Session, settings: Settings) -> tuple[User, int, bool]:
    user = db.execute(select(User).where(User.username == SHARED_DEMO_USERNAME)).scalar_one_or_none()
    if user is not None:
        report_total = db.execute(select(func.count(Report.id)).where(Report.demo_user_id == user.id)).scalar_one()
        role_keys = user_role_keys(db, user.id)
        if user.is_active and "DEMO" in role_keys and report_total > 0:
            return user, int(report_total), False

    _acquire_demo_provision_lock(db)

    user = db.execute(select(User).where(User.username == SHARED_DEMO_USERNAME)).scalar_one_or_none()
    provisioned = False

    if user is None:
        user = User(
            username=SHARED_DEMO_USERNAME,
            email=None,
            auth_source=AUTH_SOURCE_DEMO,
            password_hash=hash_password(secrets.token_urlsafe(24)),
            is_active=True,
            must_change_password=False,
        )
        db.add(user)
        db.flush()

    user.auth_source = AUTH_SOURCE_DEMO
    user.is_active = True
    user.must_change_password = False

    applied_roles = replace_user_roles(db, user, ["DEMO"])
    if "DEMO" not in applied_roles:
        raise RuntimeError("DEMO role is not configured")

    report_total = db.execute(select(func.count(Report.id)).where(Report.demo_user_id == user.id)).scalar_one()
    if report_total == 0:
        storage = ObjectStorageService(settings)
        report_total = _seed_demo_reports(db=db, settings=settings, storage=storage, user=user)
        provisioned = True

    return user, int(report_total), provisioned


def create_demo_workspace(db: Session, settings: Settings) -> tuple[User, int, int]:
    cleaned_users = cleanup_stale_demo_users(db, settings)

    username = f"demo_{secrets.token_hex(8)}"
    user = User(
        username=username,
        email=None,
        auth_source=AUTH_SOURCE_DEMO,
        password_hash=hash_password(secrets.token_urlsafe(24)),
        is_active=True,
        must_change_password=False,
    )
    db.add(user)
    db.flush()
    applied_roles = replace_user_roles(db, user, ["DEMO"])
    if "DEMO" not in applied_roles:
        raise RuntimeError("DEMO role is not configured")

    storage = ObjectStorageService(settings)
    imported_reports = _seed_demo_reports(db=db, settings=settings, storage=storage, user=user)
    return user, imported_reports, cleaned_users

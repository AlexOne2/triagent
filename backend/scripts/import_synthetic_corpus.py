from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import delete, or_, select

from app.api.routes import (
    _create_report,
    _original_message_content_type,
    _store_original_message,
    _store_report_attachments,
)
from app.db.session import SessionLocal
from app.models.attachment import Attachment
from app.models.report import IngestSource, Report, ReportStatus, ResolutionDisposition
from app.models.report_resolution import ReportResolution, ResolutionAction
from app.models.security_audit import AuditActorType
from app.schemas import ReportCreate
from app.services.analysis import calculate_risk, extract_urls, hash_reporter
from app.services.auth import create_security_audit_event
from app.services.campaign_clustering import CampaignClusteringService
from app.services.eml_parser import parse_eml
from app.services.object_storage import ObjectStorageError, ObjectStorageService
from app.services.msg_parser import parse_msg
from app.services.url_resolution import build_url_analysis, resolved_urls_for_scoring
from app.core.config import get_settings
from app.services.url_resolution import build_url_analysis

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS_ROOT = REPO_ROOT / "test_data" / "synthetic-corpus"
ACTOR = "synthetic-corpus-importer"


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


def _reset_report_fields(report: Report, payload: ReportCreate) -> int:
    settings = get_settings()
    now = datetime.now(timezone.utc)

    urls = payload.urls_json or extract_urls(payload.body_text, payload.body_html)
    url_analysis = payload.url_analysis_json or build_url_analysis(urls, settings=settings)
    event_time = payload.date or payload.received_at or now

    mailbox_domain = payload.mailbox_domain
    if not mailbox_domain and payload.reporter_email and "@" in payload.reporter_email:
        mailbox_domain = payload.reporter_email.split("@")[-1].lower()

    reporter_hash = payload.reporter_hash or hash_reporter(payload.reporter_email, settings.reporter_hash_salt)

    risk_score = calculate_risk(
        subject=payload.subject,
        body_text=payload.body_text,
        from_addr=payload.from_addr,
        mailbox_domain=mailbox_domain,
        urls=urls,
        resolved_urls=resolved_urls_for_scoring(urls, url_analysis),
        from_display_name=payload.from_display_name,
    )

    report.message_id = payload.message_id
    report.received_at = payload.received_at or payload.date or event_time
    report.subject = payload.subject
    report.from_addr = payload.from_addr
    report.from_display_name = payload.from_display_name
    report.to_addrs = payload.to_addrs or None
    report.cc_addrs = payload.cc_addrs or None
    report.date = payload.date
    report.body_text = payload.body_text
    report.body_html = payload.body_html
    report.headers_json = payload.headers_json
    report.urls_json = urls
    report.url_analysis_json = url_analysis or None
    report.reporter_hash = reporter_hash
    report.mailbox_domain = mailbox_domain
    report.raw_source = payload.raw_source
    report.risk_score = risk_score
    report.status = ReportStatus.OPEN
    report.classification_code = payload.classification_code
    report.ingest_source = IngestSource.UPLOAD
    report.sender = payload.sender
    report.reply_to = payload.reply_to or None
    report.in_reply_to = payload.in_reply_to
    report.return_path = payload.return_path
    report.originating_ip = payload.originating_ip
    report.originating_rdns = payload.originating_rdns
    report.resolution_note = None
    report.flagged_artifacts_json = None
    report.resolved_at = None
    report.last_resolved_by = None
    return risk_score


def _replace_report_artifacts(
    *,
    db,
    report: Report,
    raw_bytes: bytes,
    filename: str,
    message_format: str,
    parsed_attachments: list[object],
    storage: ObjectStorageService,
) -> None:
    existing_attachments = db.execute(select(Attachment).where(Attachment.report_id == report.id)).scalars().all()
    for attachment in existing_attachments:
        if attachment.s3_key:
            storage.delete_attachment(attachment.s3_key)
    if report.original_s3_key:
        storage.delete_original_message(report.original_s3_key)

    db.execute(delete(Attachment).where(Attachment.report_id == report.id))

    report.original_filename = None
    report.original_content_type = None
    report.original_size_bytes = None
    report.original_sha256 = None
    report.original_s3_key = None

    _store_original_message(
        report=report,
        raw_bytes=raw_bytes,
        filename=filename,
        content_type=_original_message_content_type(filename, None, file_type=message_format),
        file_type=message_format,
        storage=storage,
    )
    _store_report_attachments(
        db=db,
        report_id=report.id,
        parsed_attachments=parsed_attachments,
        storage=storage,
    )


def _clear_synthetic_resolution_history(db, report_id: int) -> None:
    db.execute(
        delete(ReportResolution).where(
            ReportResolution.report_id == report_id,
            ReportResolution.actor == ACTOR,
        )
    )


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


def _find_existing_report(db, *, parsed_report: dict[str, Any], raw_sha256: str) -> Report | None:
    predicates = [Report.original_sha256 == raw_sha256]
    message_id = parsed_report.get("message_id")
    if message_id:
        predicates.append(Report.message_id == message_id)
    return db.execute(select(Report).where(or_(*predicates)).limit(1)).scalar_one_or_none()


def _apply_expected_resolution(db, report: Report, *, disposition: str | None, classification_code: str | None, note: str) -> None:
    resolved_disposition = _report_resolution_disposition(disposition)
    if resolved_disposition is None:
        return

    next_status = _report_status_for_disposition(disposition)
    resolved_at = datetime.now(timezone.utc)
    report.status = next_status
    report.classification_code = classification_code
    report.resolution_note = note
    report.flagged_artifacts_json = None
    report.resolved_at = resolved_at
    report.last_resolved_by = ACTOR

    db.add(
        ReportResolution(
            report_id=report.id,
            action=ResolutionAction.RESOLVE,
            disposition=resolved_disposition,
            status_after=next_status,
            classification_code=classification_code,
            note=note,
            flagged_artifacts_json=None,
            actor=ACTOR,
            actor_user_id=None,
            actor_api_key_id=None,
        )
    )
    create_security_audit_event(
        db,
        action="REPORT_RESOLVED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "source": "synthetic_corpus",
            "status_after": next_status.value,
            "disposition": resolved_disposition.value,
            "classification_code": classification_code,
        },
        actor_type=AuditActorType.SYSTEM,
    )


def import_synthetic_corpus(
    *,
    corpus_root: Path,
    split: str,
    apply_expected_resolution: bool,
    dry_run: bool,
    limit: int | None,
    refresh_existing: bool,
) -> dict[str, int]:
    manifest = _load_json(corpus_root / "manifest.json")
    split_payload = _load_json(corpus_root / "splits" / f"{split}.json")
    redirect_fixtures = _load_json(corpus_root / "redirect-fixtures.json").get("fixtures", {})
    fixture_fetcher = _build_fixture_fetcher(redirect_fixtures)
    samples_by_id = {item["sample_id"]: item for item in manifest["samples"]}
    sample_ids = list(split_payload["sample_ids"])
    if limit is not None:
        sample_ids = sample_ids[:limit]

    summary = {"considered": 0, "imported": 0, "refreshed": 0, "skipped_existing": 0, "resolved": 0}

    if dry_run:
        for sample_id in sample_ids:
            entry = samples_by_id[sample_id]
            print(
                f"[dry-run] would import {sample_id} from {entry['relative_path']} "
                f"as {entry.get('classification_code') or 'UNCLASSIFIED'}"
            )
            summary["considered"] += 1
        return summary

    db = SessionLocal()
    storage = ObjectStorageService()
    clustering = CampaignClusteringService(db)
    try:
        for sample_id in sample_ids:
            summary["considered"] += 1
            entry = samples_by_id[sample_id]
            sample_path = corpus_root / entry["relative_path"]
            raw_bytes = sample_path.read_bytes()
            parsed_report, parsed_attachments = _parse_sample(raw_bytes, entry["message_format"])

            existing = _find_existing_report(db, parsed_report=parsed_report, raw_sha256=entry["sha256"])
            if existing is not None and not refresh_existing:
                summary["skipped_existing"] += 1
                print(f"skip {sample_id}: report {existing.id} already present")
                continue

            payload_data = dict(parsed_report)
            payload_data["mailbox_domain"] = entry.get("mailbox_domain")
            urls = extract_urls(parsed_report.get("body_text"), parsed_report.get("body_html"))
            payload_data["url_analysis_json"] = build_url_analysis(
                urls,
                resolve_urls=True,
                fetcher=fixture_fetcher,
            )
            payload = ReportCreate(**payload_data)
            is_refresh = existing is not None and refresh_existing

            if is_refresh:
                report = existing
                risk_score = _reset_report_fields(report, payload)
                try:
                    _replace_report_artifacts(
                        db=db,
                        report=report,
                        raw_bytes=raw_bytes,
                        filename=entry["file_name"],
                        message_format=entry["message_format"],
                        parsed_attachments=parsed_attachments,
                        storage=storage,
                    )
                except ObjectStorageError:
                    db.rollback()
                    raise
                _clear_synthetic_resolution_history(db, report.id)
                assignment = clustering.auto_assign_report(
                    report,
                    actor_snapshot=ACTOR,
                    actor_user_id=None,
                    actor_api_key_id=None,
                    allow_reassign=True,
                )
            else:
                report, risk_score = _create_report(payload, db, IngestSource.UPLOAD)

                try:
                    _store_original_message(
                        report=report,
                        raw_bytes=raw_bytes,
                        filename=entry["file_name"],
                        content_type=_original_message_content_type(
                            entry["file_name"],
                            None,
                            file_type=entry["message_format"],
                        ),
                        file_type=entry["message_format"],
                        storage=storage,
                    )
                    _store_report_attachments(
                        db=db,
                        report_id=report.id,
                        parsed_attachments=parsed_attachments,
                        storage=storage,
                    )
                except ObjectStorageError:
                    db.rollback()
                    raise

                assignment = clustering.auto_assign_report(
                    report,
                    actor_snapshot=ACTOR,
                    actor_user_id=None,
                    actor_api_key_id=None,
                    allow_reassign=False,
                )
            create_security_audit_event(
                db,
                action="REPORT_REFRESHED" if is_refresh else "REPORT_INGESTED",
                outcome="SUCCESS",
                target_type="report",
                target_id=str(report.id),
                metadata={
                    "source": "synthetic_corpus",
                    "sample_id": sample_id,
                    "split": split,
                    "risk_score": risk_score,
                    "attachment_count": len(parsed_attachments),
                    "campaign_id": assignment.campaign_id,
                    "campaign_created": assignment.created_new,
                    "refreshed_existing": is_refresh,
                },
                actor_type=AuditActorType.SYSTEM,
            )

            if apply_expected_resolution:
                _apply_expected_resolution(
                    db,
                    report,
                    disposition=entry.get("disposition"),
                    classification_code=entry.get("classification_code"),
                    note=f"Synthetic corpus import: {sample_id}",
                )
                if entry.get("disposition"):
                    summary["resolved"] += 1

            db.commit()
            if is_refresh:
                summary["refreshed"] += 1
            else:
                summary["imported"] += 1
            print(
                f"{'refreshed' if is_refresh else 'imported'} {sample_id}: report={report.id} risk={risk_score} "
                f"urls={len(urls)} attachments={len(parsed_attachments)}"
            )
    finally:
        db.close()

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Import synthetic corpus samples into the Triagent database.")
    parser.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT, help="Synthetic corpus root directory.")
    parser.add_argument("--split", default="gold", help="Corpus split to import, for example gold.")
    parser.add_argument("--limit", type=int, default=None, help="Optional max number of samples to import from the split.")
    parser.add_argument(
        "--open-only",
        action="store_true",
        help="Import reports but leave them OPEN instead of applying expected resolutions.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the samples that would be imported without writing to the database or object storage.",
    )
    parser.add_argument(
        "--refresh-existing",
        action="store_true",
        help="Update matching synthetic reports in place instead of skipping them.",
    )
    args = parser.parse_args()

    summary = import_synthetic_corpus(
        corpus_root=args.corpus_root,
        split=args.split,
        apply_expected_resolution=not args.open_only,
        dry_run=args.dry_run,
        limit=args.limit,
        refresh_existing=args.refresh_existing,
    )
    print(
        "summary: "
        f"considered={summary['considered']} "
        f"imported={summary['imported']} "
        f"refreshed={summary['refreshed']} "
        f"skipped_existing={summary['skipped_existing']} "
        f"resolved={summary['resolved']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

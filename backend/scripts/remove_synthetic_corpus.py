from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import delete, or_, select

from app.db.session import SessionLocal
from app.models.attachment import Attachment
from app.models.campaign import Campaign
from app.models.report import Report
from app.services.campaign_clustering import CampaignClusteringService
from app.services.eml_parser import parse_eml
from app.services.msg_parser import parse_msg
from app.services.object_storage import ObjectStorageService

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS_ROOT = REPO_ROOT / "test_data" / "synthetic-corpus"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sample_ids_for_split(corpus_root: Path, split: str) -> list[str]:
    split_path = corpus_root / "splits" / f"{split}.json"
    split_payload = _load_json(split_path)
    return list(split_payload["sample_ids"])


def _matching_reports(db, *, original_sha256: str | None, message_id: str | None) -> list[Report]:
    predicates = []
    if original_sha256:
        predicates.append(Report.original_sha256 == original_sha256)
    if message_id:
        predicates.append(Report.message_id == message_id)
    if not predicates:
        return []
    return db.execute(select(Report).where(or_(*predicates)).order_by(Report.id.asc())).scalars().all()


def _message_id_for_sample(raw_bytes: bytes, file_name: str) -> str | None:
    lowered = file_name.lower()
    if lowered.endswith(".msg"):
        parsed, _ = parse_msg(raw_bytes)
    else:
        parsed, _ = parse_eml(raw_bytes)
    return parsed.get("message_id")


def remove_synthetic_corpus(
    *,
    corpus_root: Path,
    split: str,
    dry_run: bool,
    limit: int | None,
) -> dict[str, int]:
    manifest = _load_json(corpus_root / "manifest.json")
    sample_ids = _sample_ids_for_split(corpus_root, split)
    if limit is not None:
        sample_ids = sample_ids[:limit]

    samples_by_id = {item["sample_id"]: item for item in manifest["samples"]}
    db = SessionLocal()
    storage = ObjectStorageService()
    clustering = CampaignClusteringService(db)
    summary = {"considered": 0, "matched_reports": 0, "deleted_reports": 0, "deleted_campaigns": 0}

    try:
        reports_to_delete: list[Report] = []
        affected_campaign_ids: set[int] = set()
        seen_report_ids: set[int] = set()

        for sample_id in sample_ids:
            summary["considered"] += 1
            entry = samples_by_id[sample_id]
            sample_path = corpus_root / entry["relative_path"]
            raw_bytes = sample_path.read_bytes()
            message_id = _message_id_for_sample(raw_bytes, entry["file_name"])

            matches = _matching_reports(
                db,
                original_sha256=entry.get("sha256"),
                message_id=message_id,
            )
            if not matches:
                continue
            summary["matched_reports"] += len(matches)
            for report in matches:
                if report.id in seen_report_ids:
                    continue
                seen_report_ids.add(report.id)
                reports_to_delete.append(report)
                if report.campaign_id is not None:
                    affected_campaign_ids.add(report.campaign_id)

        if dry_run:
            for report in reports_to_delete:
                print(f"[dry-run] would delete report {report.id} subject={report.subject!r}")
            return summary

        attachment_rows = []
        report_ids = [report.id for report in reports_to_delete]
        if report_ids:
            attachment_rows = (
                db.execute(select(Attachment).where(Attachment.report_id.in_(report_ids)).order_by(Attachment.id.asc()))
                .scalars()
                .all()
            )

        for attachment in attachment_rows:
            if attachment.s3_key:
                storage.delete_attachment(attachment.s3_key)

        for report in reports_to_delete:
            if report.original_s3_key:
                storage.delete_original_message(report.original_s3_key)
            db.delete(report)

        db.flush()

        for campaign_id in sorted(affected_campaign_ids):
            clustering.refresh_campaign(campaign_id)

        empty_campaigns = (
            db.execute(select(Campaign).where(Campaign.report_count <= 0))
            .scalars()
            .all()
        )
        for campaign in empty_campaigns:
            db.delete(campaign)
            summary["deleted_campaigns"] += 1

        summary["deleted_reports"] = len(reports_to_delete)
        db.commit()
        for report in reports_to_delete:
            print(f"deleted report {report.id} subject={report.subject!r}")
    finally:
        db.close()

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove previously imported synthetic corpus reports.")
    parser.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT, help="Synthetic corpus root directory.")
    parser.add_argument("--split", default="gold", help="Corpus split to remove, for example gold.")
    parser.add_argument("--limit", type=int, default=None, help="Optional max number of split entries to process.")
    parser.add_argument("--dry-run", action="store_true", help="Print matching reports without deleting them.")
    args = parser.parse_args()

    summary = remove_synthetic_corpus(
        corpus_root=args.corpus_root,
        split=args.split,
        dry_run=args.dry_run,
        limit=args.limit,
    )
    print(
        "summary: "
        f"considered={summary['considered']} "
        f"matched_reports={summary['matched_reports']} "
        f"deleted_reports={summary['deleted_reports']} "
        f"deleted_campaigns={summary['deleted_campaigns']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

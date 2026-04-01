from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.models.campaign import Campaign
from app.models.report import CampaignAssignmentMethod, Report
from app.services.campaign_clustering import CampaignClusteringService


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def run_backfill(start: datetime | None, end: datetime | None) -> None:
    db = SessionLocal()
    try:
        service = CampaignClusteringService(db)
        stats = service.recluster(
            start=start,
            end=end,
            actor_snapshot="campaign-maintenance",
            actor_user_id=None,
            actor_api_key_id=None,
        )
        db.commit()
        print("Campaign backfill complete")
        print(stats)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def run_metrics() -> None:
    db = SessionLocal()
    try:
        total_reports = db.execute(select(func.count()).select_from(Report)).scalar_one()
        assigned_reports = db.execute(
            select(func.count()).select_from(Report).where(Report.campaign_id.is_not(None))
        ).scalar_one()
        manual_reports = db.execute(
            select(func.count())
            .select_from(Report)
            .where(Report.campaign_assignment_method == CampaignAssignmentMethod.MANUAL)
        ).scalar_one()
        total_campaigns = db.execute(select(func.count()).select_from(Campaign)).scalar_one()
        locked_campaigns = db.execute(
            select(func.count()).select_from(Campaign).where(Campaign.is_locked.is_(True))
        ).scalar_one()
        avg_size = db.execute(select(func.avg(Campaign.report_count)).select_from(Campaign)).scalar_one()

        print(
            {
                "total_reports": int(total_reports or 0),
                "assigned_reports": int(assigned_reports or 0),
                "manual_reports": int(manual_reports or 0),
                "total_campaigns": int(total_campaigns or 0),
                "locked_campaigns": int(locked_campaigns or 0),
                "avg_campaign_size": float(avg_size or 0.0),
            }
        )
    finally:
        db.close()


def _normalize_message_id(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    if cleaned.startswith("<") and cleaned.endswith(">") and len(cleaned) > 2:
        cleaned = cleaned[1:-1]
    return cleaned.strip().lower() or None


def run_evaluate(manifest_path: str) -> None:
    path = Path(manifest_path)
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    manifest = json.loads(path.read_text(encoding="utf-8"))
    entries = manifest.get("messages", [])
    if not isinstance(entries, list) or not entries:
        raise ValueError("Manifest has no messages")

    expected: dict[str, dict[str, str]] = {}
    for item in entries:
        if not isinstance(item, dict):
            continue
        message_id = _normalize_message_id(str(item.get("message_id") or ""))
        family = str(item.get("expected_family") or "").strip()
        kind = str(item.get("kind") or "").strip()
        if not message_id or not family:
            continue
        expected[message_id] = {"family": family, "kind": kind}

    if not expected:
        raise ValueError("Manifest does not contain valid message_id entries")

    db = SessionLocal()
    try:
        rows = db.execute(
            select(Report.id, Report.message_id, Report.campaign_id, Report.status)
        ).all()

        observed_by_message_id: dict[str, dict] = {}
        for report_id, message_id, campaign_id, status in rows:
            normalized = _normalize_message_id(message_id)
            if not normalized:
                continue
            if normalized in expected:
                observed_by_message_id[normalized] = {
                    "report_id": report_id,
                    "campaign_id": campaign_id,
                    "status": status.value if hasattr(status, "value") else str(status),
                }

        total_expected = len(expected)
        total_found = len(observed_by_message_id)
        missing = total_expected - total_found

        # Campaign-only evaluation set.
        family_to_campaigns: dict[str, list[int | None]] = defaultdict(list)
        campaign_to_families: dict[int, list[str]] = defaultdict(list)

        for message_id, meta in expected.items():
            if meta["kind"] != "campaign":
                continue
            observed = observed_by_message_id.get(message_id)
            campaign_id = observed["campaign_id"] if observed else None
            family = meta["family"]
            family_to_campaigns[family].append(campaign_id)
            if campaign_id is not None:
                campaign_to_families[int(campaign_id)].append(family)

        family_scores: dict[str, dict[str, float | int]] = {}
        weighted_dominant = 0
        weighted_total = 0
        fragmented_families = 0

        for family, campaign_ids in sorted(family_to_campaigns.items()):
            total = len(campaign_ids)
            assigned = [cid for cid in campaign_ids if cid is not None]
            assigned_total = len(assigned)
            distinct_campaigns = len(set(assigned))
            if assigned_total == 0:
                dominant_size = 0
                purity = 0.0
            else:
                counts = Counter(assigned)
                dominant_size = counts.most_common(1)[0][1]
                purity = dominant_size / assigned_total

            if distinct_campaigns > 1:
                fragmented_families += 1

            weighted_dominant += dominant_size
            weighted_total += assigned_total
            family_scores[family] = {
                "expected_count": total,
                "assigned_count": assigned_total,
                "distinct_campaigns": distinct_campaigns,
                "dominant_cluster_size": dominant_size,
                "family_purity": round(purity, 4),
            }

        # Campaign contamination: for each observed campaign among campaign-kind messages,
        # what share belongs to its dominant expected family?
        campaign_precision_numer = 0
        campaign_precision_denom = 0
        contamination_campaigns = 0
        for campaign_id, families in campaign_to_families.items():
            counts = Counter(families)
            dominant = counts.most_common(1)[0][1]
            total = len(families)
            campaign_precision_numer += dominant
            campaign_precision_denom += total
            if len(counts) > 1:
                contamination_campaigns += 1

        summary = {
            "dataset": manifest.get("summary", {}).get("dataset_name", "unknown"),
            "manifest_path": str(path),
            "total_expected": total_expected,
            "total_found_in_db": total_found,
            "missing_reports": missing,
            "campaign_eval_expected_messages": sum(len(v) for v in family_to_campaigns.values()),
            "weighted_family_purity": round((weighted_dominant / weighted_total), 4) if weighted_total else 0.0,
            "fragmented_families": fragmented_families,
            "family_count": len(family_to_campaigns),
            "campaign_dominant_family_precision": round(
                campaign_precision_numer / campaign_precision_denom, 4
            )
            if campaign_precision_denom
            else 0.0,
            "contaminated_campaigns": contamination_campaigns,
        }

        print(json.dumps({"summary": summary, "families": family_scores}, indent=2))
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Campaign maintenance utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    backfill = subparsers.add_parser("backfill", help="Backfill/recluster campaign assignments")
    backfill.add_argument("--start", default=None)
    backfill.add_argument("--end", default=None)

    recluster = subparsers.add_parser("recluster", help="Recluster report assignments in a date window")
    recluster.add_argument("--start", default=None)
    recluster.add_argument("--end", default=None)

    subparsers.add_parser("metrics", help="Print campaign quality diagnostics")
    evaluate = subparsers.add_parser("evaluate", help="Evaluate clustering against a manifest")
    evaluate.add_argument("--manifest", default="/workspace/test_data/demo-dataset-50/manifest.json")

    args = parser.parse_args()
    if args.command in {"backfill", "recluster"}:
        run_backfill(_parse_dt(args.start), _parse_dt(args.end))
        return
    if args.command == "metrics":
        run_metrics()
        return
    if args.command == "evaluate":
        run_evaluate(args.manifest)


if __name__ == "__main__":
    main()

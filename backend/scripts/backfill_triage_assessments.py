from __future__ import annotations

import argparse
from dataclasses import asdict

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.report import Report
from app.services.triage_scoring import TRIAGE_SCORING_VERSION, build_report_triage_assessment_for_report


def _apply_triage_snapshot(report: Report) -> None:
    assessment = build_report_triage_assessment_for_report(report)
    report.triage_bucket = assessment.bucket
    report.triage_threat_score = assessment.threat_score
    report.triage_bulk_benign_score = assessment.bulk_benign_score
    report.triage_investigation_priority_score = assessment.investigation_priority_score
    report.triage_automation_confidence_score = assessment.automation_confidence_score
    report.triage_analyst_worthy = assessment.analyst_worthy
    report.triage_assessment_version = TRIAGE_SCORING_VERSION
    report.triage_assessment_json = asdict(assessment)


def backfill_triage_assessments(*, limit: int | None = None, refresh_existing: bool = False) -> dict[str, int]:
    db = SessionLocal()
    processed = 0
    updated = 0
    try:
        query = select(Report).order_by(Report.id.asc())
        if limit is not None:
            query = query.limit(limit)
        reports = db.execute(query).scalars().all()

        for report in reports:
            processed += 1
            if (
                not refresh_existing
                and report.triage_assessment_json
                and report.triage_assessment_version == TRIAGE_SCORING_VERSION
            ):
                continue
            _apply_triage_snapshot(report)
            updated += 1

        db.commit()
        return {"processed": processed, "updated": updated}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill persisted triage assessments on reports.")
    parser.add_argument("--limit", type=int, default=None, help="Only process the first N reports.")
    parser.add_argument(
        "--refresh-existing",
        action="store_true",
        help="Recompute reports that already have a persisted triage snapshot.",
    )
    args = parser.parse_args()

    summary = backfill_triage_assessments(limit=args.limit, refresh_existing=args.refresh_existing)
    print(
        f"Processed {summary['processed']} reports; updated {summary['updated']} triage assessment snapshots."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

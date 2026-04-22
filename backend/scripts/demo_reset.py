from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.services.object_storage import ObjectStorageError, ObjectStorageService
from scripts.import_synthetic_corpus import DEFAULT_CORPUS_ROOT, import_synthetic_corpus
from scripts.seed import seed


INGEST_TABLES = (
    "attachments",
    "report_features",
    "campaign_events",
    "report_resolutions",
    "reports",
    "campaigns",
)

AUDIT_TABLES = (
    "audit_exports",
    "audit_chain_state",
    "security_audit_events",
)


def _truncate_tables(*, keep_audit: bool) -> None:
    tables = list(INGEST_TABLES)
    if not keep_audit:
        tables.extend(AUDIT_TABLES)

    db = SessionLocal()
    try:
        sql = "TRUNCATE TABLE\n  " + ",\n  ".join(tables) + "\nRESTART IDENTITY CASCADE;"
        db.execute(text(sql))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _clear_report_artifacts() -> int:
    storage = ObjectStorageService()
    return storage.remove_prefix("reports/")


def _clear_filesystem_audit_exports() -> int:
    settings = get_settings()
    if settings.audit_export_storage != "filesystem":
        return 0

    audit_path = Path(settings.audit_export_path)
    if not audit_path.exists():
        return 0

    file_count = sum(1 for item in audit_path.rglob("*") if item.is_file())
    shutil.rmtree(audit_path)
    return file_count


def demo_reset(
    *,
    corpus_root: Path,
    split: str,
    include_seed: bool,
    keep_audit: bool,
    apply_expected_resolution: bool,
    limit: int | None,
) -> dict[str, int]:
    _truncate_tables(keep_audit=keep_audit)

    removed_artifacts = _clear_report_artifacts()
    removed_audit_exports = 0 if keep_audit else _clear_filesystem_audit_exports()

    if include_seed:
        seed()

    summary = import_synthetic_corpus(
        corpus_root=corpus_root,
        split=split,
        apply_expected_resolution=apply_expected_resolution,
        dry_run=False,
        limit=limit,
        refresh_existing=False,
    )
    summary["removed_artifacts"] = removed_artifacts
    summary["removed_audit_exports"] = removed_audit_exports
    summary["seeded"] = 1 if include_seed else 0
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset the demo dataset and reload a deterministic synthetic corpus.")
    parser.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT, help="Synthetic corpus root directory.")
    parser.add_argument("--split", default="gold", help="Corpus split to import, for example gold.")
    parser.add_argument("--limit", type=int, default=None, help="Optional max number of samples to import from the split.")
    parser.add_argument(
        "--include-seed",
        action="store_true",
        help="Load the lightweight seed dataset before importing the synthetic corpus.",
    )
    parser.add_argument(
        "--keep-audit",
        action="store_true",
        help="Preserve audit events and export manifests instead of clearing them during the reset.",
    )
    parser.add_argument(
        "--apply-expected-resolution",
        action="store_true",
        help="Apply expected synthetic resolutions instead of leaving imported reports OPEN for demo walkthroughs.",
    )
    args = parser.parse_args()

    try:
        summary = demo_reset(
            corpus_root=args.corpus_root,
            split=args.split,
            include_seed=args.include_seed,
            keep_audit=args.keep_audit,
            apply_expected_resolution=args.apply_expected_resolution,
            limit=args.limit,
        )
    except ObjectStorageError as exc:
        raise SystemExit(str(exc)) from exc

    print(
        "demo-reset summary: "
        f"imported={summary['imported']} "
        f"resolved={summary['resolved']} "
        f"removed_artifacts={summary['removed_artifacts']} "
        f"removed_audit_exports={summary['removed_audit_exports']} "
        f"seeded={summary['seeded']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

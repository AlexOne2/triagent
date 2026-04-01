from __future__ import annotations

from sqlalchemy import text

from app.db.session import SessionLocal


TRUNCATE_SQL = """
TRUNCATE TABLE
  attachments,
  report_features,
  campaign_events,
  report_resolutions,
  reports,
  campaigns
RESTART IDENTITY CASCADE;
"""


def main() -> None:
    db = SessionLocal()
    try:
        db.execute(text(TRUNCATE_SQL))
        db.commit()
        print("Ingested mail/campaign data reset complete.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()

from datetime import datetime, timedelta, timezone

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.report import IngestSource, Report, ReportStatus
from app.services.analysis import calculate_risk, extract_urls
from app.services.campaign_clustering import CampaignClusteringService

SAMPLES = [
    {
        "subject": "Urgent: Password reset required",
        "from_addr": "security@contoso-support.com",
        "body_text": "Please reset your password immediately at https://contoso-support.com/reset",
        "mailbox_domain": "contoso.com",
    },
    {
        "subject": "Invoice overdue",
        "from_addr": "billing@vendor-payments.ru",
        "body_text": "Invoice is overdue. Pay here: https://tinyurl.com/pay-now",
        "mailbox_domain": "contoso.com",
    },
    {
        "subject": "Shared file: Q4 review",
        "from_addr": "sharepoint@contoso.com",
        "body_text": "View the document at https://contoso.sharepoint.com/sites/review",
        "mailbox_domain": "contoso.com",
    },
]


def seed():
    db = SessionLocal()
    try:
        if db.query(Report).count() > 0:
            print("Seed data already exists; skipping.")
            return

        now = datetime.now(timezone.utc)
        clustering = CampaignClusteringService(db)
        for idx, sample in enumerate(SAMPLES):
            urls = extract_urls(sample.get("body_text"), sample.get("body_html"))
            event_time = now - timedelta(hours=idx * 6)
            risk_score = calculate_risk(
                subject=sample.get("subject"),
                body_text=sample.get("body_text"),
                from_addr=sample.get("from_addr"),
                mailbox_domain=sample.get("mailbox_domain"),
                urls=urls,
            )

            report = Report(
                subject=sample.get("subject"),
                from_addr=sample.get("from_addr"),
                body_text=sample.get("body_text"),
                mailbox_domain=sample.get("mailbox_domain"),
                urls_json=urls,
                received_at=event_time,
                date=event_time,
                risk_score=risk_score,
                status=ReportStatus.OPEN,
                ingest_source=IngestSource.UPLOAD,
            )
            db.add(report)
            db.flush()
            clustering.auto_assign_report(
                report,
                actor_snapshot="seed-script",
                actor_user_id=None,
                actor_api_key_id=None,
                allow_reassign=False,
            )

        db.commit()
        print("Seed data inserted.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()

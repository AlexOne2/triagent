from datetime import datetime, timedelta, timezone

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.cluster import Cluster
from app.models.report import Report
from app.services.analysis import calculate_risk, compute_fingerprint, extract_urls, normalize_subject

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
        if db.query(Cluster).count() > 0:
            print("Seed data already exists; skipping.")
            return

        now = datetime.now(timezone.utc)
        for idx, sample in enumerate(SAMPLES):
            urls = extract_urls(sample.get("body_text"), sample.get("body_html"))
            fingerprint = compute_fingerprint(
                sample.get("subject"),
                sample.get("from_addr"),
                sample.get("body_text"),
                sample.get("body_html"),
                urls,
            )
            event_time = now - timedelta(hours=idx * 6)
            subject_norm = normalize_subject(sample.get("subject"))
            from_domain = sample.get("from_addr").split("@")[-1]
            risk_score = calculate_risk(
                subject=sample.get("subject"),
                body_text=sample.get("body_text"),
                from_addr=sample.get("from_addr"),
                mailbox_domain=sample.get("mailbox_domain"),
                urls=urls,
            )

            cluster = Cluster(
                fingerprint=fingerprint,
                subject_norm=subject_norm,
                from_domain=from_domain,
                first_seen=event_time,
                last_seen=event_time,
                report_count=1,
                risk_score=risk_score,
            )
            db.add(cluster)
            db.flush()

            report = Report(
                cluster_id=cluster.id,
                subject=sample.get("subject"),
                from_addr=sample.get("from_addr"),
                body_text=sample.get("body_text"),
                mailbox_domain=sample.get("mailbox_domain"),
                urls_json=urls,
                received_at=event_time,
                date=event_time,
            )
            db.add(report)

        db.commit()
        print("Seed data inserted.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()

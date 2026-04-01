from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.models.campaign import Campaign, CampaignEvent, CampaignEventAction, ReportFeature
from app.models.report import CampaignAssignmentMethod, Report
from app.services.campaign_features import (
    hamming_similarity,
    jaccard_similarity,
    subject_similarity,
    temporal_decay,
    upsert_report_feature,
)


@dataclass
class CampaignSummary:
    campaign: Campaign
    subject_samples: list[str]
    body_hashes: list[str]
    from_domains: Counter[str]
    reply_to_domains: set[str]
    return_path_domains: set[str]
    url_domains: set[str]
    attachment_hashes: set[str]
    originating_ips: set[str]
    last_seen: datetime | None
    report_count: int


@dataclass
class AssignmentResult:
    campaign_id: int
    created_new: bool
    changed: bool
    score: float
    explanation: dict[str, Any]


class CampaignClusteringService:
    ALGORITHM_VERSION = "v1"
    ASSIGN_THRESHOLD = 0.82
    BORDERLINE_THRESHOLD = 0.68
    MARGIN_THRESHOLD = 0.08
    STRONG_SIGNAL_THRESHOLD = 0.58
    LOW_CONFIDENCE_ASSIGN_THRESHOLD = 0.60

    WEIGHTS = {
        "attachment_overlap": 0.30,
        "url_domain_jaccard": 0.20,
        "from_domain_match": 0.12,
        "subject_similarity": 0.14,
        "body_similarity": 0.14,
        "routing_signals": 0.05,
        "ip_temporal": 0.05,
    }

    def __init__(self, db: Session) -> None:
        self.db = db

    def _candidate_campaign_ids(self, feature: ReportFeature, report_id: int) -> set[int]:
        rows = self.db.execute(
            select(ReportFeature, Report.campaign_id)
            .join(Report, Report.id == ReportFeature.report_id)
            .where(Report.id != report_id, Report.campaign_id.is_not(None))
        ).all()

        feature_url_domains = set(feature.url_domains_json or [])
        feature_attachment_hashes = set(feature.attachment_hashes_json or [])
        candidate_ids: set[int] = set()

        for item_feature, campaign_id in rows:
            if campaign_id is None:
                continue
            if item_feature.from_domain and feature.from_domain and item_feature.from_domain == feature.from_domain:
                candidate_ids.add(campaign_id)
                continue
            if (
                item_feature.return_path_domain
                and feature.return_path_domain
                and item_feature.return_path_domain == feature.return_path_domain
            ):
                candidate_ids.add(campaign_id)
                continue
            if feature_url_domains and set(item_feature.url_domains_json or []).intersection(feature_url_domains):
                candidate_ids.add(campaign_id)
                continue
            if feature_attachment_hashes and set(item_feature.attachment_hashes_json or []).intersection(feature_attachment_hashes):
                candidate_ids.add(campaign_id)
                continue
        return candidate_ids

    def _campaign_summary(self, campaign: Campaign) -> CampaignSummary:
        rows = self.db.execute(
            select(ReportFeature, Report)
            .join(Report, Report.id == ReportFeature.report_id)
            .where(Report.campaign_id == campaign.id)
            .order_by(Report.created_at.desc())
        ).all()

        subject_samples: list[str] = []
        body_hashes: list[str] = []
        from_domains: Counter[str] = Counter()
        reply_to_domains: set[str] = set()
        return_path_domains: set[str] = set()
        url_domains: set[str] = set()
        attachment_hashes: set[str] = set()
        originating_ips: set[str] = set()
        last_seen: datetime | None = None

        for feature, report in rows:
            if feature.subject_norm:
                subject_samples.append(feature.subject_norm)
            if feature.body_simhash:
                body_hashes.append(feature.body_simhash)
            if feature.from_domain:
                from_domains[feature.from_domain] += 1
            reply_to_domains.update(feature.reply_to_domains_json or [])
            if feature.return_path_domain:
                return_path_domains.add(feature.return_path_domain)
            url_domains.update(feature.url_domains_json or [])
            attachment_hashes.update((feature.attachment_hashes_json or []))
            if feature.originating_ip:
                originating_ips.add(feature.originating_ip)
            seen_at = report.received_at or report.created_at
            if seen_at and (last_seen is None or seen_at > last_seen):
                last_seen = seen_at

        return CampaignSummary(
            campaign=campaign,
            subject_samples=subject_samples[:10],
            body_hashes=body_hashes[:10],
            from_domains=from_domains,
            reply_to_domains=reply_to_domains,
            return_path_domains=return_path_domains,
            url_domains=url_domains,
            attachment_hashes=attachment_hashes,
            originating_ips=originating_ips,
            last_seen=last_seen,
            report_count=len(rows),
        )

    def _score_against_summary(
        self,
        feature: ReportFeature,
        summary: CampaignSummary,
    ) -> tuple[float, dict[str, Any]]:
        attachment_overlap = jaccard_similarity(feature.attachment_hashes_json or [], summary.attachment_hashes)
        url_domain_jaccard = jaccard_similarity(feature.url_domains_json or [], summary.url_domains)
        dominant_from = summary.from_domains.most_common(1)[0][0] if summary.from_domains else None
        from_domain_match = 1.0 if dominant_from and feature.from_domain == dominant_from else 0.0

        best_subject = max(
            (subject_similarity(feature.subject_norm, item) for item in summary.subject_samples),
            default=0.0,
        )
        best_body = max(
            (hamming_similarity(feature.body_simhash, item) for item in summary.body_hashes),
            default=0.0,
        )

        reply_match = 1.0 if set(feature.reply_to_domains_json or []).intersection(summary.reply_to_domains) else 0.0
        return_path_match = 1.0 if feature.return_path_domain and feature.return_path_domain in summary.return_path_domains else 0.0
        routing_signals = 0.5 * reply_match + 0.5 * return_path_match

        ip_match = 1.0 if feature.originating_ip and feature.originating_ip in summary.originating_ips else 0.0
        now = datetime.now(timezone.utc)
        last_seen = summary.last_seen or now
        days_old = max((now - last_seen).total_seconds() / 86400.0, 0.0)
        temporal = temporal_decay(days_old)
        ip_temporal = 0.5 * ip_match + 0.5 * temporal

        base = (
            self.WEIGHTS["attachment_overlap"] * attachment_overlap
            + self.WEIGHTS["url_domain_jaccard"] * url_domain_jaccard
            + self.WEIGHTS["from_domain_match"] * from_domain_match
            + self.WEIGHTS["subject_similarity"] * best_subject
            + self.WEIGHTS["body_similarity"] * best_body
            + self.WEIGHTS["routing_signals"] * routing_signals
            + self.WEIGHTS["ip_temporal"] * ip_temporal
        )

        boost = 0.0
        if attachment_overlap > 0:
            boost += 0.15
        if url_domain_jaccard >= 0.5:
            boost += 0.10

        score = min(1.0, base + boost)
        explanation = {
            "attachment_overlap": round(attachment_overlap, 4),
            "url_domain_jaccard": round(url_domain_jaccard, 4),
            "from_domain_match": round(from_domain_match, 4),
            "subject_similarity": round(best_subject, 4),
            "body_similarity": round(best_body, 4),
            "routing_signals": round(routing_signals, 4),
            "ip_temporal": round(ip_temporal, 4),
            "boost": round(boost, 4),
            "score": round(score, 4),
        }
        return score, explanation

    def _new_campaign(self, *, report: Report, name: str | None = None, confidence_score: float | None = None) -> Campaign:
        seed = f"{uuid.uuid4().hex}:{report.id}:{report.created_at.isoformat() if report.created_at else ''}"
        campaign = Campaign(
            campaign_key=hashlib.sha256(seed.encode("utf-8")).hexdigest(),
            name=name,
            first_seen=report.received_at or report.created_at,
            last_seen=report.received_at or report.created_at,
            report_count=0,
            confidence_score=confidence_score,
            is_locked=False,
            algorithm_version=self.ALGORITHM_VERSION,
        )
        self.db.add(campaign)
        self.db.flush()
        return campaign

    def create_campaign(self, *, report: Report, name: str | None = None, confidence_score: float | None = None) -> Campaign:
        return self._new_campaign(report=report, name=name, confidence_score=confidence_score)

    def _refresh_campaign(self, campaign_id: int) -> None:
        # SessionLocal uses autoflush=False, so ensure pending report reassignment writes
        # are visible before recomputing aggregate campaign fields.
        self.db.flush()
        campaign = self.db.get(Campaign, campaign_id)
        if campaign is None:
            return

        report_rows = self.db.execute(
            select(Report.received_at, Report.created_at, Report.campaign_assignment_score)
            .where(Report.campaign_id == campaign_id)
        ).all()

        if not report_rows:
            campaign.report_count = 0
            campaign.first_seen = None
            campaign.last_seen = None
            campaign.confidence_score = None
            return

        seen_times = [received_at or created_at for received_at, created_at, _ in report_rows if (received_at or created_at)]
        campaign.report_count = len(report_rows)
        campaign.first_seen = min(seen_times) if seen_times else None
        campaign.last_seen = max(seen_times) if seen_times else None

        scored = [score for _, _, score in report_rows if score is not None]
        if scored:
            campaign.confidence_score = round(sum(scored) / len(scored), 4)
        else:
            campaign.confidence_score = None

        campaign.algorithm_version = self.ALGORITHM_VERSION

    def _create_campaign_event(
        self,
        *,
        campaign_id: int,
        action: CampaignEventAction,
        actor_snapshot: str,
        report_id: int | None = None,
        from_campaign_id: int | None = None,
        to_campaign_id: int | None = None,
        score: float | None = None,
        features_json: dict[str, Any] | None = None,
        actor_user_id: int | None = None,
        actor_api_key_id: int | None = None,
    ) -> None:
        self.db.add(
            CampaignEvent(
                campaign_id=campaign_id,
                action=action,
                report_id=report_id,
                from_campaign_id=from_campaign_id,
                to_campaign_id=to_campaign_id,
                score=score,
                features_json=features_json,
                actor_user_id=actor_user_id,
                actor_api_key_id=actor_api_key_id,
                actor_snapshot=actor_snapshot,
            )
        )

    def auto_assign_report(
        self,
        report: Report,
        *,
        actor_snapshot: str,
        actor_user_id: int | None,
        actor_api_key_id: int | None,
        allow_reassign: bool = True,
    ) -> AssignmentResult:
        feature = upsert_report_feature(self.db, report)

        candidate_campaign_ids = self._candidate_campaign_ids(feature, report.id)
        candidates = []
        for campaign_id in candidate_campaign_ids:
            campaign = self.db.get(Campaign, campaign_id)
            if campaign is None:
                continue
            if campaign.is_locked and campaign_id != report.campaign_id:
                continue
            summary = self._campaign_summary(campaign)
            score, explanation = self._score_against_summary(feature, summary)
            candidates.append((campaign, score, explanation))

        candidates.sort(key=lambda item: item[1], reverse=True)
        best_score = candidates[0][1] if candidates else 0.0
        second_score = candidates[1][1] if len(candidates) > 1 else 0.0
        margin = best_score - second_score

        selected_campaign: Campaign | None = None
        created_new = False

        top_features = candidates[0][2] if candidates else {}
        strong_signal_match = bool(
            candidates
            and (
                top_features.get("attachment_overlap", 0.0) > 0.0
                or (
                    top_features.get("from_domain_match", 0.0) >= 1.0
                    and top_features.get("url_domain_jaccard", 0.0) >= 0.8
                    and (
                        top_features.get("subject_similarity", 0.0) >= 0.45
                        or top_features.get("body_similarity", 0.0) >= 0.6
                    )
                    and best_score >= self.STRONG_SIGNAL_THRESHOLD
                )
            )
        )
        low_confidence_safe_assign = bool(
            candidates
            and best_score >= self.LOW_CONFIDENCE_ASSIGN_THRESHOLD
            and top_features.get("from_domain_match", 0.0) >= 1.0
            and top_features.get("url_domain_jaccard", 0.0) >= 0.8
        )

        if candidates and best_score >= self.ASSIGN_THRESHOLD and margin >= self.MARGIN_THRESHOLD:
            selected_campaign = candidates[0][0]
        elif strong_signal_match or low_confidence_safe_assign:
            selected_campaign = candidates[0][0]
        elif best_score >= self.BORDERLINE_THRESHOLD:
            selected_campaign = self._new_campaign(report=report, confidence_score=best_score)
            created_new = True
        elif report.campaign_id is not None and not allow_reassign:
            selected_campaign = self.db.get(Campaign, report.campaign_id)
        else:
            selected_campaign = self._new_campaign(report=report, confidence_score=best_score if best_score > 0 else None)
            created_new = True

        previous_campaign_id = report.campaign_id
        changed = selected_campaign is not None and previous_campaign_id != selected_campaign.id

        explanation: dict[str, Any] = {
            "candidate_campaign_count": len(candidates),
            "best_score": round(best_score, 4),
            "second_score": round(second_score, 4),
            "margin": round(margin, 4),
            "selected_campaign_id": selected_campaign.id if selected_campaign else None,
            "created_new_campaign": created_new,
            "strong_signal_match": strong_signal_match,
            "low_confidence_safe_assign": low_confidence_safe_assign,
        }
        if candidates:
            explanation["top_match_features"] = candidates[0][2]

        if selected_campaign is None:
            raise ValueError("Failed to select a campaign")

        if changed or report.campaign_assignment_method is None:
            report.campaign_id = selected_campaign.id
            report.campaign_assignment_method = CampaignAssignmentMethod.AUTO
            report.campaign_assignment_score = round(best_score, 4) if best_score else None
            report.campaign_assignment_explanation_json = explanation

            self._create_campaign_event(
                campaign_id=selected_campaign.id,
                action=CampaignEventAction.AUTO_ASSIGN,
                actor_snapshot=actor_snapshot,
                report_id=report.id,
                from_campaign_id=previous_campaign_id,
                to_campaign_id=selected_campaign.id,
                score=best_score if best_score else None,
                features_json=explanation,
                actor_user_id=actor_user_id,
                actor_api_key_id=actor_api_key_id,
            )

        if previous_campaign_id and previous_campaign_id != selected_campaign.id:
            self._refresh_campaign(previous_campaign_id)
        self._refresh_campaign(selected_campaign.id)
        self.db.flush()

        return AssignmentResult(
            campaign_id=selected_campaign.id,
            created_new=created_new,
            changed=changed,
            score=best_score,
            explanation=explanation,
        )

    def recluster(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        actor_snapshot: str,
        actor_user_id: int | None,
        actor_api_key_id: int | None,
    ) -> dict[str, int]:
        query = select(Report).order_by(Report.created_at.asc(), Report.id.asc())
        if start is not None:
            query = query.where(Report.created_at >= start)
        if end is not None:
            query = query.where(Report.created_at <= end)
        reports = self.db.execute(query).scalars().all()

        processed = 0
        reassigned = 0
        created_campaigns = 0
        skipped_manual = 0

        for report in reports:
            if report.campaign_assignment_method == CampaignAssignmentMethod.MANUAL:
                skipped_manual += 1
                continue
            current_campaign = self.db.get(Campaign, report.campaign_id) if report.campaign_id else None
            if current_campaign and current_campaign.is_locked:
                continue

            previous_campaign = report.campaign_id
            result = self.auto_assign_report(
                report,
                actor_snapshot=actor_snapshot,
                actor_user_id=actor_user_id,
                actor_api_key_id=actor_api_key_id,
                allow_reassign=True,
            )
            processed += 1
            if result.created_new:
                created_campaigns += 1
            if previous_campaign != result.campaign_id:
                reassigned += 1

        return {
            "processed_reports": processed,
            "reassigned_reports": reassigned,
            "created_campaigns": created_campaigns,
            "skipped_manual_reports": skipped_manual,
        }

    def recount_all_campaigns(self) -> None:
        campaign_ids = self.db.execute(select(Campaign.id)).scalars().all()
        for campaign_id in campaign_ids:
            self._refresh_campaign(campaign_id)
        self.db.flush()

    def refresh_campaign(self, campaign_id: int) -> None:
        self._refresh_campaign(campaign_id)
        self.db.flush()

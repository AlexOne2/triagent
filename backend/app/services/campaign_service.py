from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.campaign import Campaign, CampaignEvent, CampaignEventAction
from app.models.report import CampaignAssignmentMethod, Report
from app.services.campaign_clustering import CampaignClusteringService


class CampaignServiceError(RuntimeError):
    pass


class CampaignService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.clustering = CampaignClusteringService(db)

    def _create_event(
        self,
        *,
        campaign_id: int,
        action: CampaignEventAction,
        actor_snapshot: str,
        report_id: int | None = None,
        from_campaign_id: int | None = None,
        to_campaign_id: int | None = None,
        score: float | None = None,
        features_json: dict | None = None,
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

    def create_campaign_for_report(self, report: Report, *, name: str | None = None) -> Campaign:
        campaign = self.clustering.create_campaign(report=report, name=name)
        self.db.flush()
        return campaign

    def reassign_report(
        self,
        *,
        report: Report,
        target_campaign: Campaign,
        actor_snapshot: str,
        actor_user_id: int | None,
        actor_api_key_id: int | None,
        reason: str | None = None,
    ) -> Report:
        if target_campaign.is_locked and report.campaign_id != target_campaign.id:
            raise CampaignServiceError("Cannot assign to a locked campaign")

        from_campaign_id = report.campaign_id
        report.campaign_id = target_campaign.id
        report.campaign_assignment_method = CampaignAssignmentMethod.MANUAL
        report.campaign_assignment_score = None
        report.campaign_assignment_explanation_json = {
            "manual_override": True,
            "reason": reason,
            "assigned_at": datetime.now(timezone.utc).isoformat(),
        }

        self._create_event(
            campaign_id=target_campaign.id,
            action=CampaignEventAction.MANUAL_REASSIGN,
            actor_snapshot=actor_snapshot,
            report_id=report.id,
            from_campaign_id=from_campaign_id,
            to_campaign_id=target_campaign.id,
            features_json={"reason": reason},
            actor_user_id=actor_user_id,
            actor_api_key_id=actor_api_key_id,
        )

        if from_campaign_id and from_campaign_id != target_campaign.id:
            self.clustering.refresh_campaign(from_campaign_id)
        self.clustering.refresh_campaign(target_campaign.id)
        self.db.flush()
        return report

    def merge_campaigns(
        self,
        *,
        source_campaign_ids: list[int],
        target_campaign_id: int,
        actor_snapshot: str,
        actor_user_id: int | None,
        actor_api_key_id: int | None,
    ) -> Campaign:
        target = self.db.get(Campaign, target_campaign_id)
        if target is None:
            raise CampaignServiceError("Target campaign not found")

        source_campaign_ids = sorted({item for item in source_campaign_ids if item != target_campaign_id})
        if not source_campaign_ids:
            raise CampaignServiceError("No source campaigns provided")

        moved_count = 0
        for source_id in source_campaign_ids:
            source = self.db.get(Campaign, source_id)
            if source is None:
                continue
            reports = self.db.execute(select(Report).where(Report.campaign_id == source_id)).scalars().all()
            for report in reports:
                report.campaign_id = target.id
                report.campaign_assignment_method = CampaignAssignmentMethod.MANUAL
                report.campaign_assignment_score = None
                report.campaign_assignment_explanation_json = {
                    "manual_override": True,
                    "reason": "campaign_merge",
                    "source_campaign_id": source_id,
                }
                moved_count += 1

            self._create_event(
                campaign_id=target.id,
                action=CampaignEventAction.MERGE,
                actor_snapshot=actor_snapshot,
                from_campaign_id=source_id,
                to_campaign_id=target.id,
                features_json={"moved_report_count": len(reports)},
                actor_user_id=actor_user_id,
                actor_api_key_id=actor_api_key_id,
            )
            self.clustering.refresh_campaign(source_id)

        self.clustering.refresh_campaign(target.id)
        self.db.flush()

        if moved_count == 0:
            raise CampaignServiceError("No reports moved during merge")
        return target

    def split_campaign(
        self,
        *,
        source_campaign_id: int,
        report_ids: list[int],
        new_campaign_name: str | None,
        actor_snapshot: str,
        actor_user_id: int | None,
        actor_api_key_id: int | None,
    ) -> Campaign:
        source_campaign = self.db.get(Campaign, source_campaign_id)
        if source_campaign is None:
            raise CampaignServiceError("Source campaign not found")

        reports = self.db.execute(
            select(Report).where(Report.id.in_(report_ids), Report.campaign_id == source_campaign_id)
        ).scalars().all()
        if not reports:
            raise CampaignServiceError("No reports found to split")

        new_campaign = self.create_campaign_for_report(reports[0], name=new_campaign_name)
        for report in reports:
            report.campaign_id = new_campaign.id
            report.campaign_assignment_method = CampaignAssignmentMethod.MANUAL
            report.campaign_assignment_score = None
            report.campaign_assignment_explanation_json = {
                "manual_override": True,
                "reason": "campaign_split",
                "source_campaign_id": source_campaign_id,
            }

        self._create_event(
            campaign_id=new_campaign.id,
            action=CampaignEventAction.SPLIT,
            actor_snapshot=actor_snapshot,
            from_campaign_id=source_campaign_id,
            to_campaign_id=new_campaign.id,
            features_json={"split_report_ids": [report.id for report in reports]},
            actor_user_id=actor_user_id,
            actor_api_key_id=actor_api_key_id,
        )

        self.clustering.refresh_campaign(source_campaign_id)
        self.clustering.refresh_campaign(new_campaign.id)
        self.db.flush()
        return new_campaign

    def set_lock_state(
        self,
        *,
        campaign: Campaign,
        locked: bool,
        reason: str | None,
        actor_snapshot: str,
        actor_user_id: int | None,
        actor_api_key_id: int | None,
    ) -> Campaign:
        campaign.is_locked = locked
        campaign.lock_reason = reason if locked else None
        self._create_event(
            campaign_id=campaign.id,
            action=CampaignEventAction.LOCK if locked else CampaignEventAction.UNLOCK,
            actor_snapshot=actor_snapshot,
            features_json={"reason": reason} if reason else None,
            actor_user_id=actor_user_id,
            actor_api_key_id=actor_api_key_id,
        )
        self.db.flush()
        return campaign

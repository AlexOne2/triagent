from collections import Counter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile, status
from sqlalchemy import Text, case, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.security_deps import Principal, require_permission, request_meta
from app.core.config import get_settings
from app.models.attachment import Attachment
from app.models.campaign import Campaign, CampaignEvent
from app.models.report import (
    CLASSIFICATION_CODES,
    ArtifactKind,
    CampaignAssignmentMethod,
    IngestSource,
    Report,
    ReportStatus,
    ResolutionAction,
    ResolutionDisposition,
)
from app.models.security_audit import AuditActorType
from app.models.report_resolution import ReportResolution
from app.schemas import (
    AttachmentOut,
    CampaignEventOut,
    CampaignLockRequest,
    CampaignMergeRequest,
    CampaignOut,
    CampaignReassignRequest,
    CampaignReclusterRequest,
    CampaignReclusterResult,
    CampaignSplitRequest,
    DashboardAddressPoint,
    DashboardClassificationPoint,
    DashboardKpis,
    DashboardMaliciousSafe,
    DashboardOverviewOut,
    DashboardResolutionPoint,
    DashboardTriageBucketPoint,
    FileIngestBatchResult,
    FileIngestResult,
    FlaggedArtifactIn,
    FlaggedArtifactOut,
    AttackMappingOut,
    LookalikeAnalysisOut,
    ReportAssistDraftOut,
    ReportCreate,
    ReportAuthSummaryOut,
    ReportListOut,
    ReportOut,
    ReportResolutionOut,
    ReportResult,
    ReportTriageAssessmentOut,
    ReportUpdate,
    ResolveReportRequest,
    TriageBucket,
    UrlAnalysisOut,
)
from app.services.analysis import calculate_risk, extract_urls, hash_reporter
from app.services.attack_mapping import AttackMappingInput, build_attack_mapping
from app.services.auth_summary import build_auth_summary
from app.services.campaign_clustering import CampaignClusteringService
from app.services.campaign_service import CampaignService, CampaignServiceError
from app.services.auth import create_security_audit_event
from app.services.eml_parser import parse_eml
from app.services.evidence_export import EvidenceExportService
from app.services.lookalike_detection import build_lookalike_analysis
from app.services.msg_parser import MsgParseError, parse_msg
from app.services.object_storage import ObjectStorageError, ObjectStorageService, normalize_filename, sanitize_filename
from app.services.report_assist import AssistArtifactOption, ReportAssistInput, build_report_assist_draft
from app.services.triage_scoring import (
    TRIAGE_SCORING_VERSION,
    ReportTriageAssessmentResult,
    build_report_triage_assessment_for_report,
)
from app.services.url_resolution import build_static_url_analysis, build_url_analysis, extract_url_domain, resolved_urls_for_scoring

router = APIRouter(prefix="/api", tags=["api"])

TRIAGE_BUCKET_ORDER: tuple[TriageBucket, ...] = (
    "NEEDS_INVESTIGATION",
    "AUTOMATION_READY",
    "BULK_SPAM",
    "LIKELY_BENIGN",
    "UNCERTAIN",
)


def _is_demo_principal(principal: Principal) -> bool:
    return bool(principal.role_keys and "DEMO" in principal.role_keys)


def _report_scope_predicate(principal: Principal):
    if _is_demo_principal(principal):
        if principal.user_id is None:
            raise HTTPException(status_code=403, detail="Demo session is invalid")
        return Report.demo_user_id == principal.user_id
    return Report.demo_user_id.is_(None)


def _apply_report_scope(query, principal: Principal):
    return query.where(_report_scope_predicate(principal))


def _scoped_report_or_404(
    db: Session,
    report_id: int,
    principal: Principal,
    *,
    for_update: bool = False,
) -> Report:
    query = _apply_report_scope(select(Report).where(Report.id == report_id), principal)
    if for_update:
        query = query.with_for_update()
    report = db.execute(query).scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def _principal_actor_type(principal: Principal) -> AuditActorType:
    if principal.kind == "user":
        return AuditActorType.USER
    if principal.kind == "api_key":
        return AuditActorType.API_KEY
    if principal.kind == "legacy":
        return AuditActorType.LEGACY
    return AuditActorType.SYSTEM


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _resolve_window(start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    resolved_end = _as_utc(end) if end else now
    resolved_start = _as_utc(start) if start else (resolved_end - timedelta(days=90))
    if resolved_start > resolved_end:
        raise HTTPException(status_code=400, detail="start must be before end")
    return resolved_start, resolved_end


def _evidence_filename(report_id: int, extension: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"report-{report_id}-evidence-{stamp}.{extension}"


def _campaign_evidence_filename(campaign_id: int, extension: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"campaign-{campaign_id}-evidence-{stamp}.{extension}"


def _report_ioc_filename(report_id: int, extension: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"report-{report_id}-iocs-{stamp}.{extension}"


def _download_content_disposition(filename: str | None, *, default: str) -> str:
    normalized = normalize_filename(filename, default=default)
    fallback = sanitize_filename(normalized, default=default)
    encoded = quote(normalized, safe="")
    return f'attachment; filename="{fallback}"; filename*=UTF-8\'\'{encoded}'


def _default_original_message_filename(filename: str | None, *, file_type: str) -> str:
    normalized_type = file_type.lower()
    if normalized_type == "eml":
        return normalize_filename(filename, default="message.eml")
    if normalized_type == "msg":
        return normalize_filename(filename, default="message.msg")
    return normalize_filename(filename, default="original-message.bin")


def _original_message_content_type(filename: str | None, content_type: str | None, *, file_type: str) -> str:
    if content_type and content_type.strip() and content_type.strip().lower() != "application/octet-stream":
        return content_type
    normalized_type = file_type.lower()
    lowered_filename = (filename or "").lower()
    if normalized_type == "eml" or lowered_filename.endswith(".eml"):
        return "message/rfc822"
    if normalized_type == "msg" or lowered_filename.endswith(".msg"):
        return "application/vnd.ms-outlook"
    return "application/octet-stream"


def _normalize_email(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    if not cleaned or "@" not in cleaned:
        return None
    return cleaned


def _searchable_text(value):
    return func.lower(func.coalesce(cast(value, Text), ""))


def _matches_report_search(value, like: str):
    return _searchable_text(value).like(like)


def _build_report_search_predicate(search_term: str):
    like = f"%{search_term.strip().lower()}%"

    attachment_match = (
        select(Attachment.id)
        .where(
            Attachment.report_id == Report.id,
            or_(
                _matches_report_search(Attachment.filename, like),
                _matches_report_search(Attachment.content_type, like),
                _matches_report_search(Attachment.sha256, like),
            ),
        )
        .exists()
    )

    return or_(
        _matches_report_search(Report.subject, like),
        _matches_report_search(Report.from_addr, like),
        _matches_report_search(Report.from_display_name, like),
        _matches_report_search(Report.sender, like),
        _matches_report_search(Report.to_addrs, like),
        _matches_report_search(Report.cc_addrs, like),
        _matches_report_search(Report.reply_to, like),
        _matches_report_search(Report.return_path, like),
        _matches_report_search(Report.mailbox_domain, like),
        _matches_report_search(Report.message_id, like),
        _matches_report_search(Report.in_reply_to, like),
        _matches_report_search(Report.originating_ip, like),
        _matches_report_search(Report.originating_rdns, like),
        _matches_report_search(Report.urls_json, like),
        _matches_report_search(Report.url_analysis_json, like),
        _matches_report_search(Report.headers_json, like),
        _matches_report_search(Report.original_filename, like),
        _matches_report_search(Report.original_sha256, like),
        _matches_report_search(Report.classification_code, like),
        attachment_match,
    )


def _normalize_classification_filters(values: list[str] | None) -> list[str]:
    if not values:
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip().upper()
        if not cleaned:
            continue
        if cleaned not in CLASSIFICATION_CODES:
            raise HTTPException(status_code=400, detail=f"Invalid classification code: {cleaned}")
        if cleaned in seen:
            continue
        seen.add(cleaned)
        normalized.append(cleaned)
    return normalized


def _apply_report_list_filters(
    query,
    *,
    q: str | None,
    statuses: list[ReportStatus] | None,
    source: IngestSource | None,
    classification_codes: list[str] | None,
    triage_buckets: list[TriageBucket] | None,
):
    if q and q.strip():
        query = query.where(_build_report_search_predicate(q))
    if statuses:
        query = query.where(Report.status.in_(statuses))
    if source:
        query = query.where(Report.ingest_source == source)
    normalized_classifications = _normalize_classification_filters(classification_codes)
    if normalized_classifications:
        query = query.where(Report.classification_code.in_(normalized_classifications))
    if triage_buckets:
        query = query.where(Report.triage_bucket.in_(triage_buckets))
    return query


def _ranked_counts(counter: Counter[str], limit: int = 10) -> list[DashboardAddressPoint]:
    ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [DashboardAddressPoint(rank=index + 1, email=email, count=count) for index, (email, count) in enumerate(ranked)]


def _store_report_attachments(
    *,
    db: Session,
    report_id: int,
    parsed_attachments: list[object],
    storage: ObjectStorageService,
) -> list[str]:
    stored_keys: list[str] = []
    for parsed_attachment in parsed_attachments:
        stored = storage.put_attachment(
            report_id=report_id,
            filename=parsed_attachment.filename,
            content_type=parsed_attachment.content_type,
            data=parsed_attachment.data,
        )
        stored_keys.append(str(stored["s3_key"]))
        db.add(
            Attachment(
                report_id=report_id,
                filename=parsed_attachment.filename,
                content_type=parsed_attachment.content_type,
                size_bytes=stored["size_bytes"],
                sha256=stored["sha256"],
                s3_key=stored["s3_key"],
            )
        )
    return stored_keys


def _store_original_message(
    *,
    report: Report,
    raw_bytes: bytes,
    filename: str | None,
    content_type: str | None,
    file_type: str,
    storage: ObjectStorageService,
) -> str:
    stored = storage.put_original_message(
        report_id=report.id,
        filename=_default_original_message_filename(filename, file_type=file_type),
        content_type=_original_message_content_type(filename, content_type, file_type=file_type),
        data=raw_bytes,
    )
    report.original_filename = str(stored["filename"])
    report.original_content_type = str(stored["content_type"])
    report.original_size_bytes = int(stored["size_bytes"])
    report.original_sha256 = str(stored["sha256"])
    report.original_s3_key = str(stored["s3_key"])
    return report.original_s3_key


def _cleanup_stored_artifacts(
    *,
    storage: ObjectStorageService,
    original_s3_key: str | None,
    attachment_s3_keys: list[str],
) -> None:
    for s3_key in attachment_s3_keys:
        try:
            storage.delete_attachment(s3_key)
        except ObjectStorageError:
            continue
    if original_s3_key:
        try:
            storage.delete_original_message(original_s3_key)
        except ObjectStorageError:
            pass


def _normalize_artifact_value(kind: ArtifactKind, value: str) -> str:
    cleaned = value.strip()
    if kind in {
        ArtifactKind.FROM_ADDR,
        ArtifactKind.FROM_DOMAIN,
        ArtifactKind.REPLY_TO,
        ArtifactKind.RETURN_PATH,
        ArtifactKind.RETURN_PATH_DOMAIN,
        ArtifactKind.URL_DOMAIN,
        ArtifactKind.ATTACHMENT_SHA256,
    }:
        return cleaned.lower()
    return cleaned


def _extract_email_domain(value: str | None) -> str | None:
    if not value:
        return None
    parsed_addr = parseaddr(value)[1] or value
    cleaned = parsed_addr.strip().lower()
    if "@" not in cleaned:
        return None
    domain = cleaned.rsplit("@", 1)[-1].strip()
    return domain or None


def _extract_url_domain(value: str | None) -> str | None:
    return extract_url_domain(value)


def _available_artifacts(report: Report) -> dict[ArtifactKind, set[str]]:
    auth_summary = build_auth_summary(report)
    available: dict[ArtifactKind, set[str]] = {
        ArtifactKind.FROM_ADDR: set(),
        ArtifactKind.FROM_DOMAIN: set(),
        ArtifactKind.REPLY_TO: set(),
        ArtifactKind.RETURN_PATH: set(),
        ArtifactKind.RETURN_PATH_DOMAIN: set(),
        ArtifactKind.ORIGINATING_IP: set(),
        ArtifactKind.URL: set(),
        ArtifactKind.URL_DOMAIN: set(),
        ArtifactKind.ATTACHMENT_NAME: set(),
        ArtifactKind.ATTACHMENT_SHA256: set(),
    }

    if report.from_addr:
        available[ArtifactKind.FROM_ADDR].add(_normalize_artifact_value(ArtifactKind.FROM_ADDR, report.from_addr))
        from_domain = _extract_email_domain(report.from_addr)
        if from_domain:
            available[ArtifactKind.FROM_DOMAIN].add(_normalize_artifact_value(ArtifactKind.FROM_DOMAIN, from_domain))
    if report.reply_to:
        for item in report.reply_to:
            available[ArtifactKind.REPLY_TO].add(_normalize_artifact_value(ArtifactKind.REPLY_TO, item))
    if report.return_path:
        available[ArtifactKind.RETURN_PATH].add(
            _normalize_artifact_value(ArtifactKind.RETURN_PATH, report.return_path)
        )
        return_path_domain = _extract_email_domain(report.return_path)
        if return_path_domain:
            available[ArtifactKind.RETURN_PATH_DOMAIN].add(
                _normalize_artifact_value(ArtifactKind.RETURN_PATH_DOMAIN, return_path_domain)
            )
    if report.originating_ip:
        available[ArtifactKind.ORIGINATING_IP].add(
            _normalize_artifact_value(ArtifactKind.ORIGINATING_IP, report.originating_ip)
        )
    auth_spf = auth_summary.get("spf") or {}
    auth_dmarc = auth_summary.get("dmarc") or {}
    if auth_spf.get("originating_ip"):
        available[ArtifactKind.ORIGINATING_IP].add(
            _normalize_artifact_value(ArtifactKind.ORIGINATING_IP, auth_spf["originating_ip"])
        )
    if auth_spf.get("return_path_domain"):
        available[ArtifactKind.RETURN_PATH_DOMAIN].add(
            _normalize_artifact_value(ArtifactKind.RETURN_PATH_DOMAIN, auth_spf["return_path_domain"])
        )
    if auth_dmarc.get("header_from"):
        available[ArtifactKind.FROM_DOMAIN].add(
            _normalize_artifact_value(ArtifactKind.FROM_DOMAIN, auth_dmarc["header_from"])
        )
    if report.urls_json:
        for item in report.urls_json:
            available[ArtifactKind.URL].add(_normalize_artifact_value(ArtifactKind.URL, item))
            url_domain = _extract_url_domain(item)
            if url_domain:
                available[ArtifactKind.URL_DOMAIN].add(
                    _normalize_artifact_value(ArtifactKind.URL_DOMAIN, url_domain)
                )
    for item in report.url_analysis_json or []:
        final_url = item.get("final_url")
        if final_url:
            available[ArtifactKind.URL].add(_normalize_artifact_value(ArtifactKind.URL, final_url))
        final_domain = item.get("final_domain")
        if final_domain:
            available[ArtifactKind.URL_DOMAIN].add(
                _normalize_artifact_value(ArtifactKind.URL_DOMAIN, final_domain)
            )
    if report.attachments:
        for attachment in report.attachments:
            if attachment.filename:
                available[ArtifactKind.ATTACHMENT_NAME].add(
                    _normalize_artifact_value(ArtifactKind.ATTACHMENT_NAME, attachment.filename)
                )
            if attachment.sha256:
                available[ArtifactKind.ATTACHMENT_SHA256].add(
                    _normalize_artifact_value(ArtifactKind.ATTACHMENT_SHA256, attachment.sha256)
                )
    return available


def _artifact_options(report: Report, auth_summary: dict | None = None) -> list[AssistArtifactOption]:
    auth_summary = auth_summary or build_auth_summary(report)
    items: list[AssistArtifactOption] = []
    seen: set[tuple[ArtifactKind, str]] = set()

    def push(kind: ArtifactKind, value: str | None, label: str | None) -> None:
        if not value or not label:
            return
        normalized_value = _normalize_artifact_value(kind, value)
        key = (kind, normalized_value)
        if key in seen:
            return
        seen.add(key)
        items.append(AssistArtifactOption(kind=kind, value=normalized_value, label=label))

    if report.from_addr:
        push(ArtifactKind.FROM_ADDR, report.from_addr, f"From email address - {report.from_addr}")
        from_domain = _extract_email_domain(report.from_addr)
        if from_domain:
            push(ArtifactKind.FROM_DOMAIN, from_domain, f"From domain - {from_domain}")

    for reply_to in report.reply_to or []:
        push(ArtifactKind.REPLY_TO, reply_to, f"Reply-To - {reply_to}")

    if report.return_path:
        push(ArtifactKind.RETURN_PATH, report.return_path, f"Return-Path email address - {report.return_path}")
        return_path_domain = _extract_email_domain(report.return_path)
        if return_path_domain:
            push(ArtifactKind.RETURN_PATH_DOMAIN, return_path_domain, f"Return-Path domain - {return_path_domain}")

    if report.originating_ip:
        label = f"Originating IP - {report.originating_ip}"
        if report.originating_rdns:
            label += f" ({report.originating_rdns})"
        push(ArtifactKind.ORIGINATING_IP, report.originating_ip, label)

    auth_spf = auth_summary.get("spf") or {}
    if auth_spf.get("originating_ip"):
        label = f"Originating IP - {auth_spf['originating_ip']}"
        if auth_spf.get("originating_rdns"):
            label += f" ({auth_spf['originating_rdns']})"
        push(ArtifactKind.ORIGINATING_IP, auth_spf["originating_ip"], label)
    if auth_spf.get("return_path_domain"):
        push(
            ArtifactKind.RETURN_PATH_DOMAIN,
            auth_spf["return_path_domain"],
            f"Return-Path domain - {auth_spf['return_path_domain']}",
        )

    auth_dmarc = auth_summary.get("dmarc") or {}
    if auth_dmarc.get("header_from"):
        push(ArtifactKind.FROM_DOMAIN, auth_dmarc["header_from"], f"From domain - {auth_dmarc['header_from']}")

    for item in report.urls_json or []:
        push(ArtifactKind.URL, item, f"Message URL - {item}")
        url_domain = _extract_url_domain(item)
        if url_domain:
            push(ArtifactKind.URL_DOMAIN, url_domain, f"Message URL domain - {url_domain}")

    for item in report.url_analysis_json or []:
        final_url = item.get("final_url")
        if final_url and final_url != item.get("original_url"):
            push(ArtifactKind.URL, final_url, f"Resolved URL - {final_url}")
        final_domain = item.get("final_domain")
        if final_domain:
            push(ArtifactKind.URL_DOMAIN, final_domain, f"Resolved URL domain - {final_domain}")

    for attachment in report.attachments or []:
        if attachment.filename:
            push(ArtifactKind.ATTACHMENT_NAME, attachment.filename, f"Attachment file name - {attachment.filename}")
        if attachment.sha256:
            push(ArtifactKind.ATTACHMENT_SHA256, attachment.sha256, f"Attachment SHA-256 - {attachment.sha256}")

    return items


def _validate_flagged_artifacts(report: Report, flagged_artifacts: list[FlaggedArtifactIn]) -> list[dict]:
    available = _available_artifacts(report)
    normalized_items: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for artifact in flagged_artifacts:
        normalized_value = _normalize_artifact_value(artifact.kind, artifact.value)
        if normalized_value not in available.get(artifact.kind, set()):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid artifact value for kind {artifact.kind.value}",
            )
        dedupe_key = (artifact.kind.value, normalized_value)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        normalized_items.append(
            {
                "kind": artifact.kind.value,
                "value": normalized_value,
                "label": artifact.label,
            }
        )
    return normalized_items


def _resolution_status(disposition: ResolutionDisposition) -> ReportStatus:
    if disposition == ResolutionDisposition.MALICIOUS:
        return ReportStatus.PHISHING
    return ReportStatus.BENIGN


def _serialize_resolution(event: ReportResolution) -> ReportResolutionOut:
    artifacts = [
        FlaggedArtifactOut(
            kind=item["kind"],
            value=item["value"],
            label=item.get("label"),
        )
        for item in (event.flagged_artifacts_json or [])
    ]
    return ReportResolutionOut(
        id=event.id,
        action=event.action,
        disposition=event.disposition,
        status_after=event.status_after,
        classification_code=event.classification_code,
        note=event.note,
        flagged_artifacts=artifacts,
        actor=event.actor,
        actor_user_id=event.actor_user_id,
        actor_api_key_id=event.actor_api_key_id,
        created_at=event.created_at,
    )


def _serialize_report(report: Report) -> ReportOut:
    payload = ReportOut.model_validate(report)
    raw_url_analysis = report.url_analysis_json or build_static_url_analysis(report.urls_json or [])
    url_analysis = [UrlAnalysisOut.model_validate(item) for item in raw_url_analysis]
    auth_summary = ReportAuthSummaryOut.model_validate(build_auth_summary(report))
    raw_lookalike_analysis = build_lookalike_analysis(
        mailbox_domain=report.mailbox_domain,
        from_addr=report.from_addr,
        reply_to=list(report.reply_to or []),
        return_path=report.return_path,
    )
    lookalike_analysis = (
        LookalikeAnalysisOut.model_validate(raw_lookalike_analysis) if raw_lookalike_analysis else None
    )
    attack_mapping = AttackMappingOut.model_validate(
        asdict(
            build_attack_mapping(
                AttackMappingInput(
                    classification_code=report.classification_code,
                    status=report.status.value,
                    from_addr=report.from_addr,
                    reply_to=list(report.reply_to or []),
                    return_path=report.return_path,
                    urls=[item for item in (report.urls_json or []) if item],
                    url_analysis=[
                        {
                            "original_url": item.original_url,
                            "normalized_url": item.normalized_url,
                            "final_url": item.final_url,
                            "final_domain": item.final_domain,
                            "domain_changed": item.domain_changed,
                            "is_shortener": item.is_shortener,
                            "suspicious_redirect": item.suspicious_redirect,
                        }
                        for item in url_analysis
                    ],
                    attachment_names=[item.filename for item in report.attachments if item.filename],
                    auth_spf_result=str(auth_summary.spf.result or "unknown"),
                    auth_dkim_result=str(auth_summary.dkim.result or "unknown"),
                    auth_dmarc_result=str(auth_summary.dmarc.result or "unknown"),
                )
            )
        )
    )
    triage_assessment = _build_triage_assessment(
        report,
        auth_summary=auth_summary.model_dump(mode="python"),
        raw_url_analysis=raw_url_analysis,
        raw_lookalike_analysis=raw_lookalike_analysis,
    )
    return payload.model_copy(
        update={
            "auth_summary": auth_summary,
            "url_analysis_json": url_analysis,
            "attack_mapping": attack_mapping,
            "lookalike_analysis": lookalike_analysis,
            "triage_assessment": triage_assessment,
        }
    )


def _persist_triage_assessment(report: Report, assessment: ReportTriageAssessmentResult) -> None:
    report.triage_bucket = assessment.bucket
    report.triage_threat_score = assessment.threat_score
    report.triage_bulk_benign_score = assessment.bulk_benign_score
    report.triage_investigation_priority_score = assessment.investigation_priority_score
    report.triage_automation_confidence_score = assessment.automation_confidence_score
    report.triage_analyst_worthy = assessment.analyst_worthy
    report.triage_assessment_version = TRIAGE_SCORING_VERSION
    report.triage_assessment_json = asdict(assessment)


def _compute_triage_assessment(
    report: Report,
    *,
    auth_summary: dict | None = None,
    raw_url_analysis: list[dict] | None = None,
    raw_lookalike_analysis: dict | None = None,
    attachment_names: list[str] | None = None,
) -> ReportTriageAssessmentResult:
    return build_report_triage_assessment_for_report(
        report,
        attachment_names=attachment_names,
        auth_summary=auth_summary,
        raw_url_analysis=raw_url_analysis,
        raw_lookalike_analysis=raw_lookalike_analysis,
    )


def _build_triage_assessment(
    report: Report,
    *,
    auth_summary: dict | None = None,
    raw_url_analysis: list[dict] | None = None,
    raw_lookalike_analysis: dict | None = None,
) -> ReportTriageAssessmentOut:
    if report.triage_assessment_json and report.triage_assessment_version == TRIAGE_SCORING_VERSION:
        return ReportTriageAssessmentOut.model_validate(report.triage_assessment_json)
    triage = _compute_triage_assessment(
        report,
        auth_summary=auth_summary,
        raw_url_analysis=raw_url_analysis,
        raw_lookalike_analysis=raw_lookalike_analysis,
    )
    return ReportTriageAssessmentOut.model_validate(asdict(triage))


def _serialize_report_list_item(report: Report) -> ReportOut:
    payload = ReportOut.model_validate(report)
    triage_assessment = _build_triage_assessment(report)
    return payload.model_copy(update={"triage_assessment": triage_assessment})


def _create_report(
    payload: ReportCreate,
    db: Session,
    ingest_source: IngestSource,
    *,
    attachment_names: list[str] | None = None,
    demo_user_id: int | None = None,
) -> tuple[Report, int]:
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

    report = Report(
        message_id=payload.message_id,
        received_at=payload.received_at or payload.date or event_time,
        subject=payload.subject,
        from_addr=payload.from_addr,
        from_display_name=payload.from_display_name,
        to_addrs=payload.to_addrs or None,
        cc_addrs=payload.cc_addrs or None,
        date=payload.date,
        body_text=payload.body_text,
        body_html=payload.body_html,
        headers_json=payload.headers_json,
        urls_json=urls,
        url_analysis_json=url_analysis or None,
        reporter_hash=reporter_hash,
        mailbox_domain=mailbox_domain,
        raw_source=payload.raw_source,
        risk_score=risk_score,
        status=ReportStatus.OPEN,
        classification_code=payload.classification_code,
        ingest_source=ingest_source,
        sender=payload.sender,
        reply_to=payload.reply_to or None,
        in_reply_to=payload.in_reply_to,
        return_path=payload.return_path,
        originating_ip=payload.originating_ip,
        originating_rdns=payload.originating_rdns,
        demo_user_id=demo_user_id,
    )
    triage_assessment = _compute_triage_assessment(report, raw_url_analysis=url_analysis, attachment_names=attachment_names)
    _persist_triage_assessment(report, triage_assessment)
    db.add(report)
    db.flush()
    return report, risk_score


def _assign_campaign(
    db: Session,
    report: Report,
    principal: Principal,
) -> int | None:
    return None


@router.post("/report", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
def create_report(
    request: Request,
    payload: ReportCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.ingest")),
):
    try:
        report, risk_score = _create_report(payload, db, IngestSource.AUTO)
        campaign_id = _assign_campaign(db, report, principal)
        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "ingest_source": IngestSource.AUTO.value,
                "risk_score": risk_score,
                "campaign_id": campaign_id,
            },
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return ReportResult(report_id=report.id, risk_score=risk_score, campaign_id=report.campaign_id)


@router.post("/report-eml", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
async def create_report_from_eml(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.ingest")),
):
    raw_bytes = await file.read()
    try:
        parsed_report, parsed_attachments = parse_eml(raw_bytes)
        payload = ReportCreate(**parsed_report)
        report, risk_score = _create_report(
            payload,
            db,
            IngestSource.UPLOAD,
            attachment_names=[item.filename for item in parsed_attachments if item.filename],
        )
        storage = ObjectStorageService()
        original_s3_key = None
        attachment_s3_keys: list[str] = []
        try:
            original_s3_key = _store_original_message(
                report=report,
                raw_bytes=raw_bytes,
                filename=file.filename,
                content_type=file.content_type,
                file_type="eml",
                storage=storage,
            )
            attachment_s3_keys = _store_report_attachments(
                db=db,
                report_id=report.id,
                parsed_attachments=parsed_attachments,
                storage=storage,
            )
        except ObjectStorageError:
            _cleanup_stored_artifacts(
                storage=storage,
                original_s3_key=original_s3_key,
                attachment_s3_keys=attachment_s3_keys,
            )
            raise
        campaign_id = _assign_campaign(db, report, principal)
        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "ingest_source": IngestSource.UPLOAD.value,
                "risk_score": risk_score,
                "file_type": "eml",
                "attachment_count": len(parsed_attachments),
                "has_original_message": bool(report.original_s3_key),
                "campaign_id": campaign_id,
            },
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        db.commit()
    except ObjectStorageError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Artifact storage is unavailable") from exc
    except Exception:
        db.rollback()
        raise
    return ReportResult(report_id=report.id, risk_score=risk_score, campaign_id=report.campaign_id)


@router.post("/report-msg", response_model=ReportResult, status_code=status.HTTP_201_CREATED)
async def create_report_from_msg(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.ingest")),
):
    filename = (file.filename or "").lower()
    if not filename.endswith(".msg"):
        raise HTTPException(status_code=415, detail="Only .msg files are supported")

    raw_bytes = await file.read()
    try:
        parsed_report, parsed_attachments = parse_msg(raw_bytes)
        payload = ReportCreate(**parsed_report)
        report, risk_score = _create_report(
            payload,
            db,
            IngestSource.UPLOAD,
            attachment_names=[item.filename for item in parsed_attachments if item.filename],
        )

        storage = ObjectStorageService()
        original_s3_key = None
        attachment_s3_keys: list[str] = []
        try:
            original_s3_key = _store_original_message(
                report=report,
                raw_bytes=raw_bytes,
                filename=file.filename,
                content_type=file.content_type,
                file_type="msg",
                storage=storage,
            )
            attachment_s3_keys = _store_report_attachments(
                db=db,
                report_id=report.id,
                parsed_attachments=parsed_attachments,
                storage=storage,
            )
        except ObjectStorageError:
            _cleanup_stored_artifacts(
                storage=storage,
                original_s3_key=original_s3_key,
                attachment_s3_keys=attachment_s3_keys,
            )
            raise

        campaign_id = _assign_campaign(db, report, principal)
        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "ingest_source": IngestSource.UPLOAD.value,
                "risk_score": risk_score,
                "file_type": "msg",
                "attachment_count": len(parsed_attachments),
                "has_original_message": bool(report.original_s3_key),
                "campaign_id": campaign_id,
            },
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        db.commit()
    except MsgParseError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid or unsupported .msg file") from exc
    except ObjectStorageError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Artifact storage is unavailable") from exc
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    return ReportResult(report_id=report.id, risk_score=risk_score, campaign_id=report.campaign_id)


def _ingest_uploaded_bytes(
    *,
    file_name: str,
    content_type: str | None,
    raw_bytes: bytes,
    db: Session,
    principal: Principal,
    request: Request,
) -> ReportResult:
    lowered_name = file_name.lower()
    if lowered_name.endswith(".eml"):
        parsed_report, parsed_attachments = parse_eml(raw_bytes)
        payload = ReportCreate(**parsed_report)
        report, risk_score = _create_report(
            payload,
            db,
            IngestSource.UPLOAD,
            attachment_names=[item.filename for item in parsed_attachments if item.filename],
        )
        storage = ObjectStorageService()
        original_s3_key = None
        attachment_s3_keys: list[str] = []
        try:
            original_s3_key = _store_original_message(
                report=report,
                raw_bytes=raw_bytes,
                filename=file_name,
                content_type=content_type,
                file_type="eml",
                storage=storage,
            )
            attachment_s3_keys = _store_report_attachments(
                db=db,
                report_id=report.id,
                parsed_attachments=parsed_attachments,
                storage=storage,
            )
        except ObjectStorageError:
            _cleanup_stored_artifacts(
                storage=storage,
                original_s3_key=original_s3_key,
                attachment_s3_keys=attachment_s3_keys,
            )
            raise
        campaign_id = _assign_campaign(db, report, principal)
        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "ingest_source": IngestSource.UPLOAD.value,
                "risk_score": risk_score,
                "file_type": "eml",
                "attachment_count": len(parsed_attachments),
                "has_original_message": bool(report.original_s3_key),
                "campaign_id": campaign_id,
            },
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        return ReportResult(report_id=report.id, risk_score=risk_score, campaign_id=report.campaign_id)

    if lowered_name.endswith(".msg"):
        parsed_report, parsed_attachments = parse_msg(raw_bytes)
        payload = ReportCreate(**parsed_report)
        report, risk_score = _create_report(
            payload,
            db,
            IngestSource.UPLOAD,
            attachment_names=[item.filename for item in parsed_attachments if item.filename],
        )
        storage = ObjectStorageService()
        original_s3_key = None
        attachment_s3_keys: list[str] = []
        try:
            original_s3_key = _store_original_message(
                report=report,
                raw_bytes=raw_bytes,
                filename=file_name,
                content_type=content_type,
                file_type="msg",
                storage=storage,
            )
            attachment_s3_keys = _store_report_attachments(
                db=db,
                report_id=report.id,
                parsed_attachments=parsed_attachments,
                storage=storage,
            )
        except ObjectStorageError:
            _cleanup_stored_artifacts(
                storage=storage,
                original_s3_key=original_s3_key,
                attachment_s3_keys=attachment_s3_keys,
            )
            raise

        campaign_id = _assign_campaign(db, report, principal)
        create_security_audit_event(
            db,
            action="REPORT_INGESTED",
            outcome="SUCCESS",
            target_type="report",
            target_id=str(report.id),
            metadata={
                "ingest_source": IngestSource.UPLOAD.value,
                "risk_score": risk_score,
                "file_type": "msg",
                "attachment_count": len(parsed_attachments),
                "has_original_message": bool(report.original_s3_key),
                "campaign_id": campaign_id,
            },
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            actor_type=_principal_actor_type(principal),
            request_meta=request_meta(request),
        )
        return ReportResult(report_id=report.id, risk_score=risk_score, campaign_id=report.campaign_id)

    raise HTTPException(status_code=415, detail="Only .eml and .msg files are supported")


@router.post("/report-files", response_model=FileIngestBatchResult, status_code=status.HTTP_200_OK)
async def create_reports_from_files(
    request: Request,
    files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.ingest")),
):
    if not files:
        raise HTTPException(status_code=400, detail="At least one file is required")

    results: list[FileIngestResult] = []
    ingested_count = 0
    failed_count = 0

    for upload in files:
        file_name = upload.filename or "uploaded-file"
        raw_bytes = await upload.read()
        try:
            result = _ingest_uploaded_bytes(
                file_name=file_name,
                content_type=upload.content_type,
                raw_bytes=raw_bytes,
                db=db,
                principal=principal,
                request=request,
            )
            db.commit()
            ingested_count += 1
            results.append(
                FileIngestResult(
                    filename=file_name,
                    status="INGESTED",
                    report_id=result.report_id,
                    campaign_id=result.campaign_id,
                    risk_score=result.risk_score,
                )
            )
        except HTTPException as exc:
            db.rollback()
            failed_count += 1
            create_security_audit_event(
                db,
                action="REPORT_INGEST_FAILED",
                outcome="FAILURE",
                target_type="upload_file",
                target_id=file_name,
                metadata={"status_code": exc.status_code, "detail": exc.detail},
                actor_user_id=principal.user_id,
                actor_api_key_id=principal.api_key_id,
                actor_type=_principal_actor_type(principal),
                request_meta=request_meta(request),
            )
            db.commit()
            results.append(
                FileIngestResult(
                    filename=file_name,
                    status="FAILED",
                    error_code=str(exc.status_code),
                    error_message=str(exc.detail),
                )
            )
        except MsgParseError:
            db.rollback()
            failed_count += 1
            create_security_audit_event(
                db,
                action="REPORT_INGEST_FAILED",
                outcome="FAILURE",
                target_type="upload_file",
                target_id=file_name,
                metadata={"error": "invalid_msg"},
                actor_user_id=principal.user_id,
                actor_api_key_id=principal.api_key_id,
                actor_type=_principal_actor_type(principal),
                request_meta=request_meta(request),
            )
            db.commit()
            results.append(
                FileIngestResult(
                    filename=file_name,
                    status="FAILED",
                    error_code="invalid_msg",
                    error_message="Invalid or unsupported .msg file",
                )
            )
        except ObjectStorageError:
            db.rollback()
            failed_count += 1
            create_security_audit_event(
                db,
                action="REPORT_INGEST_FAILED",
                outcome="FAILURE",
                target_type="upload_file",
                target_id=file_name,
                metadata={"error": "storage_unavailable"},
                actor_user_id=principal.user_id,
                actor_api_key_id=principal.api_key_id,
                actor_type=_principal_actor_type(principal),
                request_meta=request_meta(request),
            )
            db.commit()
            results.append(
                FileIngestResult(
                    filename=file_name,
                    status="FAILED",
                    error_code="storage_unavailable",
                    error_message="Artifact storage is unavailable",
                )
            )
        except Exception:
            db.rollback()
            failed_count += 1
            create_security_audit_event(
                db,
                action="REPORT_INGEST_FAILED",
                outcome="FAILURE",
                target_type="upload_file",
                target_id=file_name,
                metadata={"error": "unexpected_error"},
                actor_user_id=principal.user_id,
                actor_api_key_id=principal.api_key_id,
                actor_type=_principal_actor_type(principal),
                request_meta=request_meta(request),
            )
            db.commit()
            results.append(
                FileIngestResult(
                    filename=file_name,
                    status="FAILED",
                    error_code="unexpected_error",
                    error_message="Unexpected ingest error",
                )
            )

    return FileIngestBatchResult(
        items=results,
        ingested_count=ingested_count,
        failed_count=failed_count,
    )


@router.get("/reports", response_model=ReportListOut)
def list_reports(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    q: str | None = Query(default=None, max_length=200),
    status: list[ReportStatus] | None = Query(default=None),
    source: IngestSource | None = Query(default=None),
    classification_code: list[str] | None = Query(default=None),
    triage_bucket: list[TriageBucket] | None = Query(default=None),
    principal: Principal = Depends(require_permission("reports.read")),
):
    filtered_query = _apply_report_list_filters(
        _apply_report_scope(select(Report), principal),
        q=q,
        statuses=status,
        source=source,
        classification_codes=classification_code,
        triage_buckets=triage_bucket,
    )
    total = db.execute(
        _apply_report_list_filters(
            _apply_report_scope(select(func.count()).select_from(Report), principal),
            q=q,
            statuses=status,
            source=source,
            classification_codes=classification_code,
            triage_buckets=triage_bucket,
        )
    ).scalar_one()
    reports = db.execute(
        filtered_query.order_by(Report.created_at.desc(), Report.id.desc()).offset(offset).limit(limit)
    ).scalars().all()
    return ReportListOut(
        items=[_serialize_report_list_item(report) for report in reports],
        total=total,
        limit=limit,
        offset=offset,
        has_more=offset + len(reports) < total,
    )


@router.get("/reports/{report_id}/attachments", response_model=list[AttachmentOut])
def list_report_attachments(
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    _scoped_report_or_404(db, report_id, principal)
    return (
        db.execute(
            select(Attachment)
            .where(Attachment.report_id == report_id)
            .order_by(Attachment.created_at.desc(), Attachment.id.desc())
        )
        .scalars()
        .all()
    )


@router.get("/reports/{report_id}/attachments/{attachment_id}/download")
def download_report_attachment(
    report_id: int,
    attachment_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    _scoped_report_or_404(db, report_id, principal)
    attachment = db.execute(
        select(Attachment).where(Attachment.id == attachment_id, Attachment.report_id == report_id)
    ).scalar_one_or_none()
    if attachment is None:
        raise HTTPException(status_code=404, detail="Attachment not found")

    storage = ObjectStorageService()
    try:
        content = storage.get_attachment(attachment.s3_key)
    except ObjectStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    filename = attachment.filename or "attachment.bin"
    media_type = attachment.content_type or "application/octet-stream"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": _download_content_disposition(filename, default="attachment.bin")},
    )


@router.get("/reports/{report_id}/original-message/download")
def download_report_original_message(
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)
    if not report.original_s3_key:
        raise HTTPException(status_code=404, detail="Original message not found")

    storage = ObjectStorageService()
    try:
        content = storage.get_original_message(report.original_s3_key)
    except ObjectStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    filename = report.original_filename or "original-message.bin"
    media_type = report.original_content_type or "application/octet-stream"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": _download_content_disposition(filename, default="original-message.bin")},
    )


@router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(
    db: Session = Depends(get_db),
    q: str | None = Query(default=None, max_length=200),
    source: IngestSource | None = Query(default=None),
    status: ReportStatus | None = Query(default=None),
    locked: bool | None = Query(default=None),
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: int | None = Query(default=None, ge=1),
    _: Principal = Depends(require_permission("campaigns.read")),
):
    query = select(Campaign).order_by(Campaign.last_seen.desc().nullslast(), Campaign.id.desc())
    query = query.where(Campaign.report_count > 0)

    if cursor is not None:
        query = query.where(Campaign.id < cursor)
    if q:
        like = f"%{q.lower()}%"
        query = query.where(
            or_(
                func.lower(Campaign.campaign_key).like(like),
                func.lower(func.coalesce(Campaign.name, "")).like(like),
            )
        )
    if locked is not None:
        query = query.where(Campaign.is_locked.is_(locked))
    if min_confidence is not None:
        query = query.where(Campaign.confidence_score >= min_confidence)
    if source or status:
        report_subquery = select(Report.campaign_id).where(Report.campaign_id == Campaign.id)
        if source:
            report_subquery = report_subquery.where(Report.ingest_source == source)
        if status:
            report_subquery = report_subquery.where(Report.status == status)
        query = query.where(report_subquery.exists())

    return db.execute(query.limit(limit)).scalars().all()


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut)
def get_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_permission("campaigns.read")),
):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.get("/campaigns/{campaign_id}/reports", response_model=list[ReportOut])
def list_campaign_reports(
    campaign_id: int,
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(require_permission("campaigns.read")),
):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return (
        db.execute(
            select(Report)
            .where(Report.campaign_id == campaign_id)
            .order_by(Report.created_at.desc(), Report.id.desc())
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )


@router.get("/campaigns/{campaign_id}/events", response_model=list[CampaignEventOut])
def list_campaign_events(
    campaign_id: int,
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=1000),
    _: Principal = Depends(require_permission("campaigns.read")),
):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return (
        db.execute(
            select(CampaignEvent)
            .where(CampaignEvent.campaign_id == campaign_id)
            .order_by(CampaignEvent.created_at.desc(), CampaignEvent.id.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )


@router.post("/campaigns/recluster", response_model=CampaignReclusterResult)
def recluster_campaigns(
    request: Request,
    payload: CampaignReclusterRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.run")),
):
    clustering = CampaignClusteringService(db)
    stats = clustering.recluster(
        start=payload.start,
        end=payload.end,
        actor_snapshot=principal.actor,
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
    )
    create_security_audit_event(
        db,
        action="CAMPAIGN_RECLUSTER_RUN",
        outcome="SUCCESS",
        target_type="campaign_window",
        target_id=f"{payload.start or 'begin'}..{payload.end or 'now'}",
        metadata=stats,
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    return CampaignReclusterResult(**stats)


@router.post("/campaigns/merge", response_model=CampaignOut)
def merge_campaigns(
    request: Request,
    payload: CampaignMergeRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.write")),
):
    service = CampaignService(db)
    try:
        campaign = service.merge_campaigns(
            source_campaign_ids=payload.source_campaign_ids,
            target_campaign_id=payload.target_campaign_id,
            actor_snapshot=principal.actor,
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
        )
    except CampaignServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    create_security_audit_event(
        db,
        action="CAMPAIGN_MERGED",
        outcome="SUCCESS",
        target_type="campaign",
        target_id=str(campaign.id),
        metadata={"source_campaign_ids": payload.source_campaign_ids},
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    db.refresh(campaign)
    return campaign


@router.post("/campaigns/split", response_model=CampaignOut)
def split_campaign(
    request: Request,
    payload: CampaignSplitRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.write")),
):
    service = CampaignService(db)
    try:
        campaign = service.split_campaign(
            source_campaign_id=payload.source_campaign_id,
            report_ids=payload.report_ids,
            new_campaign_name=payload.new_campaign_name,
            actor_snapshot=principal.actor,
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
        )
    except CampaignServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    create_security_audit_event(
        db,
        action="CAMPAIGN_SPLIT",
        outcome="SUCCESS",
        target_type="campaign",
        target_id=str(campaign.id),
        metadata={
            "source_campaign_id": payload.source_campaign_id,
            "report_ids": payload.report_ids,
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    db.refresh(campaign)
    return campaign


@router.post("/reports/{report_id}/campaign/reassign", response_model=ReportOut)
def reassign_report_campaign(
    report_id: int,
    request: Request,
    payload: CampaignReassignRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.write")),
):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    service = CampaignService(db)
    target_campaign: Campaign | None = None
    if payload.create_new:
        target_campaign = service.create_campaign_for_report(report, name=payload.new_campaign_name)
    else:
        target_campaign = db.get(Campaign, payload.target_campaign_id)
        if target_campaign is None:
            raise HTTPException(status_code=404, detail="Target campaign not found")

    try:
        report = service.reassign_report(
            report=report,
            target_campaign=target_campaign,
            actor_snapshot=principal.actor,
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
            reason="manual_reassign",
        )
    except CampaignServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    create_security_audit_event(
        db,
        action="CAMPAIGN_REPORT_REASSIGNED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={"campaign_id": report.campaign_id, "create_new": payload.create_new},
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    db.refresh(report)
    return _serialize_report(report)


@router.post("/campaigns/{campaign_id}/lock", response_model=CampaignOut)
def lock_campaign(
    campaign_id: int,
    request: Request,
    payload: CampaignLockRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.write")),
):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    service = CampaignService(db)
    campaign = service.set_lock_state(
        campaign=campaign,
        locked=True,
        reason=payload.reason,
        actor_snapshot=principal.actor,
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
    )
    create_security_audit_event(
        db,
        action="CAMPAIGN_LOCKED",
        outcome="SUCCESS",
        target_type="campaign",
        target_id=str(campaign.id),
        metadata={"reason": payload.reason},
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    db.refresh(campaign)
    return campaign


@router.post("/campaigns/{campaign_id}/unlock", response_model=CampaignOut)
def unlock_campaign(
    campaign_id: int,
    request: Request,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.write")),
):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    service = CampaignService(db)
    campaign = service.set_lock_state(
        campaign=campaign,
        locked=False,
        reason=None,
        actor_snapshot=principal.actor,
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
    )
    create_security_audit_event(
        db,
        action="CAMPAIGN_UNLOCKED",
        outcome="SUCCESS",
        target_type="campaign",
        target_id=str(campaign.id),
        metadata=None,
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    db.refresh(campaign)
    return campaign


@router.get("/dashboard/overview", response_model=DashboardOverviewOut)
def dashboard_overview(
    db: Session = Depends(get_db),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    tz: str = Query(default="UTC"),
    principal: Principal = Depends(require_permission("dashboard.read")),
):
    start_utc, end_utc = _resolve_window(start, end)
    try:
        tzinfo = ZoneInfo(tz)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid timezone") from exc

    rows = db.execute(
        select(
            Report.created_at,
            Report.status,
            Report.classification_code,
            Report.to_addrs,
            Report.from_addr,
            Report.ingest_source,
            Report.triage_bucket,
        ).where(
            Report.created_at >= start_utc,
            Report.created_at <= end_utc,
            _report_scope_predicate(principal),
        )
    ).all()

    total_ingested = len(rows)
    resolved_total = 0
    resolved_malicious = 0
    resolved_safe = 0

    classification_counter: Counter[str] = Counter()
    to_counter: Counter[str] = Counter()
    from_counter: Counter[str] = Counter()
    triage_counter: Counter[str] = Counter()

    start_local = start_utc.astimezone(tzinfo).date()
    end_local = end_utc.astimezone(tzinfo).date()
    timeseries_map: dict[str, dict[str, int]] = {}

    cursor = start_local
    while cursor <= end_local:
        key = cursor.isoformat()
        timeseries_map[key] = {"resolved_total": 0, "resolved_malicious": 0, "resolved_safe": 0}
        cursor += timedelta(days=1)

    for created_at, status_value, classification_code, to_addrs, from_addr, ingest_source, triage_bucket in rows:
        if created_at is None:
            continue
        local_key = created_at.astimezone(tzinfo).date().isoformat()

        if status_value in (ReportStatus.BENIGN, ReportStatus.PHISHING):
            resolved_total += 1
            timeseries_map[local_key]["resolved_total"] += 1
        if status_value == ReportStatus.PHISHING:
            resolved_malicious += 1
            timeseries_map[local_key]["resolved_malicious"] += 1
        if status_value == ReportStatus.BENIGN:
            resolved_safe += 1
            timeseries_map[local_key]["resolved_safe"] += 1

        classification_counter[classification_code or "UNCLASSIFIED"] += 1

        normalized_from = _normalize_email(from_addr)
        if normalized_from:
            from_counter[normalized_from] += 1

        if to_addrs:
            for addr in to_addrs:
                normalized_to = _normalize_email(addr)
                if normalized_to:
                    to_counter[normalized_to] += 1
        if ingest_source == IngestSource.AUTO:
            triage_counter[(triage_bucket or "UNCERTAIN")] += 1

    timeseries = [
        DashboardResolutionPoint(
            date=key,
            resolved_total=value["resolved_total"],
            resolved_malicious=value["resolved_malicious"],
            resolved_safe=value["resolved_safe"],
        )
        for key, value in timeseries_map.items()
    ]

    classifications = [
        DashboardClassificationPoint(code=code, count=count)
        for code, count in sorted(classification_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    triage_buckets = [
        DashboardTriageBucketPoint(bucket=bucket, count=triage_counter.get(bucket, 0))
        for bucket in TRIAGE_BUCKET_ORDER
    ]

    return DashboardOverviewOut(
        kpis=DashboardKpis(
            total_ingested=total_ingested,
            resolved_total=resolved_total,
            resolved_malicious=resolved_malicious,
            resolved_safe=resolved_safe,
        ),
        resolutions_timeseries=timeseries,
        malicious_safe=DashboardMaliciousSafe(malicious=resolved_malicious, safe=resolved_safe),
        classifications=classifications,
        triage_buckets=triage_buckets,
        top_to_addresses=_ranked_counts(to_counter),
        top_from_addresses=_ranked_counts(from_counter),
    )


@router.get("/reports/stats")
def report_stats(
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("dashboard.read")),
):
    stmt = select(
        func.count(Report.id).label("total"),
        func.sum(case((Report.status == ReportStatus.OPEN, 1), else_=0)).label("open"),
        func.sum(case((Report.status == ReportStatus.BENIGN, 1), else_=0)).label("benign"),
        func.sum(case((Report.status == ReportStatus.PHISHING, 1), else_=0)).label("phishing"),
    ).where(_report_scope_predicate(principal))
    row = db.execute(stmt).one()
    return {
        "total": int(row.total or 0),
        "open": int(row.open or 0),
        "benign": int(row.benign or 0),
        "phishing": int(row.phishing or 0),
    }


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)
    return _serialize_report(report)


@router.post("/reports/{report_id}/assist/draft", response_model=ReportAssistDraftOut)
def generate_report_assist_draft_endpoint(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)

    auth_summary = build_auth_summary(report)
    raw_url_analysis = report.url_analysis_json or build_static_url_analysis(report.urls_json or [])
    lookalike_analysis = build_lookalike_analysis(
        mailbox_domain=report.mailbox_domain,
        from_addr=report.from_addr,
        reply_to=list(report.reply_to or []),
        return_path=report.return_path,
    )
    attack_mapping = asdict(
        build_attack_mapping(
            AttackMappingInput(
                classification_code=report.classification_code,
                status=report.status.value,
                from_addr=report.from_addr,
                reply_to=list(report.reply_to or []),
                return_path=report.return_path,
                urls=[item for item in (report.urls_json or []) if item],
                url_analysis=[
                    {
                        "original_url": item.get("original_url"),
                        "normalized_url": item.get("normalized_url"),
                        "final_url": item.get("final_url"),
                        "final_domain": item.get("final_domain"),
                        "domain_changed": item.get("domain_changed"),
                        "is_shortener": item.get("is_shortener"),
                        "suspicious_redirect": item.get("suspicious_redirect"),
                    }
                    for item in raw_url_analysis
                ],
                attachment_names=[item.filename for item in report.attachments if item.filename],
                auth_spf_result=str((auth_summary.get("spf") or {}).get("result") or "unknown"),
                auth_dkim_result=str((auth_summary.get("dkim") or {}).get("result") or "unknown"),
                auth_dmarc_result=str((auth_summary.get("dmarc") or {}).get("result") or "unknown"),
            )
        )
    )
    report_input = ReportAssistInput(
        report_id=report.id,
        risk_score=report.risk_score,
        status=report.status.value,
        subject=report.subject,
        body_excerpt=((report.body_text or report.body_html or "")[:1800] or None),
        from_addr=report.from_addr,
        from_display_name=report.from_display_name,
        reply_to=list(report.reply_to or []),
        return_path=report.return_path,
        mailbox_domain=report.mailbox_domain,
        in_reply_to=report.in_reply_to,
        urls=[item for item in (report.urls_json or []) if item],
        url_analysis=raw_url_analysis,
        attachment_names=[item.filename for item in report.attachments if item.filename],
        auth_summary=auth_summary,
        lookalike_analysis=lookalike_analysis,
        attack_mapping=attack_mapping,
        artifact_options=_artifact_options(report, auth_summary),
    )
    draft = build_report_assist_draft(report_input)

    create_security_audit_event(
        db,
        action="REPORT_ASSIST_DRAFT_GENERATED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "provider": draft.provider,
            "model": draft.model,
            "confidence": draft.confidence,
            "recommended_disposition": draft.recommended_disposition.value,
            "recommended_classification_code": draft.recommended_classification_code,
            "flagged_artifacts_count": len(draft.flagged_artifacts),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    return ReportAssistDraftOut.model_validate(asdict(draft))


@router.get("/reports/{report_id}/evidence.json")
def export_report_evidence_json(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)

    service = EvidenceExportService(db)
    bundle = service.build_bundle(report)
    content = service.render_report_json(bundle)

    create_security_audit_event(
        db,
        action="REPORT_EVIDENCE_EXPORTED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "format": "json",
            "resolution_count": len(bundle.resolution_history),
            "attachment_count": len(bundle.attachments),
            "ioc_count": len(bundle.iocs),
            "attack_technique_count": len(bundle.attack_mapping.techniques),
            "audit_event_count": len(bundle.audit_trail),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{_evidence_filename(report.id, "json")}"'},
    )


@router.get("/reports/{report_id}/evidence.md")
def export_report_evidence_markdown(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)

    service = EvidenceExportService(db)
    bundle = service.build_bundle(report)
    content = service.render_markdown(bundle)

    create_security_audit_event(
        db,
        action="REPORT_EVIDENCE_EXPORTED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "format": "md",
            "resolution_count": len(bundle.resolution_history),
            "attachment_count": len(bundle.attachments),
            "audit_event_count": len(bundle.audit_trail),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_evidence_filename(report.id, "md")}"'},
    )


@router.get("/reports/{report_id}/evidence.pdf")
def export_report_evidence_pdf(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)

    service = EvidenceExportService(db)
    bundle = service.build_bundle(report)
    content = service.render_pdf(bundle)

    create_security_audit_event(
        db,
        action="REPORT_EVIDENCE_EXPORTED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "format": "pdf",
            "resolution_count": len(bundle.resolution_history),
            "attachment_count": len(bundle.attachments),
            "audit_event_count": len(bundle.audit_trail),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_evidence_filename(report.id, "pdf")}"'},
    )


@router.get("/reports/{report_id}/iocs.json")
def export_report_iocs_json(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)

    service = EvidenceExportService(db)
    bundle = service.build_bundle(report)
    content = service.render_ioc_json(bundle)

    create_security_audit_event(
        db,
        action="REPORT_EVIDENCE_EXPORTED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "format": "iocs_json",
            "ioc_count": len(bundle.iocs),
            "attack_technique_count": len(bundle.attack_mapping.techniques),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{_report_ioc_filename(report.id, "json")}"'},
    )


@router.get("/reports/{report_id}/iocs.csv")
def export_report_iocs_csv(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.read")),
):
    report = _scoped_report_or_404(db, report_id, principal)

    service = EvidenceExportService(db)
    bundle = service.build_bundle(report)
    content = service.render_ioc_csv(bundle)

    create_security_audit_event(
        db,
        action="REPORT_EVIDENCE_EXPORTED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "format": "iocs_csv",
            "ioc_count": len(bundle.iocs),
            "attack_technique_count": len(bundle.attack_mapping.techniques),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_report_ioc_filename(report.id, "csv")}"'},
    )


@router.get("/campaigns/{campaign_id}/evidence.md")
def export_campaign_evidence_markdown(
    request: Request,
    campaign_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.read")),
):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")

    service = EvidenceExportService(db)
    bundle = service.build_campaign_bundle(campaign)
    content = service.render_campaign_markdown(bundle)

    create_security_audit_event(
        db,
        action="CAMPAIGN_EVIDENCE_EXPORTED",
        outcome="SUCCESS",
        target_type="campaign",
        target_id=str(campaign.id),
        metadata={
            "format": "md",
            "report_count": bundle.report_count,
            "resolution_count": len(bundle.resolution_history),
            "audit_event_count": len(bundle.audit_trail),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_campaign_evidence_filename(campaign.id, "md")}"'},
    )


@router.get("/campaigns/{campaign_id}/evidence.pdf")
def export_campaign_evidence_pdf(
    request: Request,
    campaign_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("campaigns.read")),
):
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")

    service = EvidenceExportService(db)
    bundle = service.build_campaign_bundle(campaign)
    content = service.render_campaign_pdf(bundle)

    create_security_audit_event(
        db,
        action="CAMPAIGN_EVIDENCE_EXPORTED",
        outcome="SUCCESS",
        target_type="campaign",
        target_id=str(campaign.id),
        metadata={
            "format": "pdf",
            "report_count": bundle.report_count,
            "resolution_count": len(bundle.resolution_history),
            "audit_event_count": len(bundle.audit_trail),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{_campaign_evidence_filename(campaign.id, "pdf")}"'},
    )


@router.post("/reports/{report_id}/resolve", response_model=ReportOut)
def resolve_report(
    request: Request,
    report_id: int,
    payload: ResolveReportRequest,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.resolve")),
):
    report = _scoped_report_or_404(db, report_id, principal, for_update=True)
    if report.status != ReportStatus.OPEN:
        raise HTTPException(status_code=409, detail="Report is already resolved; reopen before resolving again")

    flagged_artifacts = _validate_flagged_artifacts(report, payload.flagged_artifacts)
    next_status = _resolution_status(payload.disposition)
    now = datetime.now(timezone.utc)

    report.status = next_status
    report.classification_code = payload.classification_code
    report.resolution_note = payload.note
    report.flagged_artifacts_json = flagged_artifacts or None
    report.resolved_at = now
    report.last_resolved_by = principal.actor

    db.add(
        ReportResolution(
            report_id=report.id,
            action=ResolutionAction.RESOLVE,
            disposition=payload.disposition,
            status_after=next_status,
            classification_code=payload.classification_code,
            note=payload.note,
            flagged_artifacts_json=flagged_artifacts or None,
            actor=principal.actor,
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
        )
    )
    create_security_audit_event(
        db,
        action="REPORT_RESOLVED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "status_after": next_status.value,
            "disposition": payload.disposition.value,
            "classification_code": payload.classification_code,
            "flagged_artifacts_count": len(flagged_artifacts),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(report)
    return _serialize_report(report)


@router.post("/reports/{report_id}/reopen", response_model=ReportOut)
def reopen_report(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.reopen")),
):
    report = _scoped_report_or_404(db, report_id, principal, for_update=True)
    if report.status == ReportStatus.OPEN:
        raise HTTPException(status_code=409, detail="Report is already open")

    report.status = ReportStatus.OPEN
    report.classification_code = None
    report.resolution_note = None
    report.flagged_artifacts_json = None
    report.resolved_at = None
    report.last_resolved_by = None

    db.add(
        ReportResolution(
            report_id=report.id,
            action=ResolutionAction.REOPEN,
            disposition=None,
            status_after=ReportStatus.OPEN,
            classification_code=None,
            note=None,
            flagged_artifacts_json=None,
            actor=principal.actor,
            actor_user_id=principal.user_id,
            actor_api_key_id=principal.api_key_id,
        )
    )
    create_security_audit_event(
        db,
        action="REPORT_REOPENED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={"status_after": ReportStatus.OPEN.value},
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(report)
    return _serialize_report(report)


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.admin_override")),
):
    report = _scoped_report_or_404(db, report_id, principal, for_update=True)

    attachment_count = len(report.attachments or [])
    has_original_message = bool(report.original_s3_key)
    storage = ObjectStorageService(get_settings())
    try:
        for attachment in report.attachments or []:
            if attachment.s3_key:
                storage.delete_attachment(attachment.s3_key)
        if report.original_s3_key:
            storage.delete_original_message(report.original_s3_key)
    except ObjectStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    db.delete(report)
    create_security_audit_event(
        db,
        action="REPORT_DELETED",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report_id),
        metadata={
            "attachment_count": attachment_count,
            "has_original_message": has_original_message,
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/reports/{report_id}/resolutions", response_model=list[ReportResolutionOut])
def list_report_resolutions(
    report_id: int,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("resolutions.read")),
):
    _scoped_report_or_404(db, report_id, principal)

    events = (
        db.execute(
            select(ReportResolution)
            .where(ReportResolution.report_id == report_id)
            .order_by(ReportResolution.created_at.desc(), ReportResolution.id.desc())
        )
        .scalars()
        .all()
    )
    return [_serialize_resolution(event) for event in events]


@router.patch("/reports/{report_id}", response_model=ReportOut)
def update_report(
    request: Request,
    report_id: int,
    payload: ReportUpdate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("reports.admin_override")),
):
    report = _scoped_report_or_404(db, report_id, principal)

    if "status" in payload.model_fields_set:
        if payload.status is None:
            raise HTTPException(status_code=400, detail="status cannot be null")
        report.status = payload.status  # type: ignore[assignment]
    if "classification_code" in payload.model_fields_set:
        report.classification_code = payload.classification_code

    create_security_audit_event(
        db,
        action="REPORT_ADMIN_OVERRIDDEN",
        outcome="SUCCESS",
        target_type="report",
        target_id=str(report.id),
        metadata={
            "status": report.status.value,
            "classification_code": report.classification_code,
            "updated_fields": sorted(payload.model_fields_set),
        },
        actor_user_id=principal.user_id,
        actor_api_key_id=principal.api_key_id,
        actor_type=_principal_actor_type(principal),
        request_meta=request_meta(request),
    )

    db.commit()
    db.refresh(report)
    return _serialize_report(report)

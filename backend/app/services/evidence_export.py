from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from io import StringIO
from typing import Any, Iterable
import csv

from fpdf import FPDF
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.api_key import ApiKey
from app.models.attachment import Attachment
from app.models.campaign import Campaign
from app.models.report import Report, ReportStatus, ResolutionAction
from app.models.report_resolution import ReportResolution
from app.models.security_audit import AuditActorType, SecurityAuditEvent
from app.models.user import User
from app.services.attack_mapping import AttackEvidenceRef, AttackMappingInput, AttackMappingResult, build_attack_mapping
from app.services.auth_summary import build_auth_summary
from app.services.lookalike_detection import build_lookalike_analysis
from app.services.url_resolution import build_static_url_analysis, extract_url_domain as resolve_url_domain


@dataclass
class EvidenceAttachment:
    filename: str | None
    content_type: str | None
    size_bytes: int | None
    sha256: str | None
    s3_key: str | None
    created_at: datetime | None


@dataclass
class EvidenceOriginalMessage:
    filename: str | None
    content_type: str | None
    size_bytes: int | None
    sha256: str | None
    storage_key: str | None


@dataclass
class EvidenceUrlHop:
    index: int
    url: str
    domain: str | None
    status_code: int | None
    location: str | None


@dataclass
class EvidenceUrl:
    original_url: str
    normalized_url: str
    initial_domain: str | None
    final_url: str | None
    final_domain: str | None
    redirect_count: int
    is_shortener: bool
    used_redirector: bool
    domain_changed: bool
    suspicious_redirect: bool
    resolution_status: str
    resolution_error: str | None
    redirect_chain: list[EvidenceUrlHop]


@dataclass
class EvidenceResolution:
    action: str
    disposition: str | None
    status_after: str
    classification_code: str | None
    note: str | None
    actor: str
    created_at: datetime | None


@dataclass
class EvidenceAuditEvent:
    created_at: datetime | None
    action: str
    outcome: str
    actor: str
    request_id: str | None
    event_uuid: str
    event_hash: str


@dataclass
class EvidenceIoc:
    type: str
    value: str
    roles: list[str]
    sources: list[str]
    derived: bool
    flagged_malicious: bool
    flag_labels: list[str]


@dataclass
class EvidenceLookalikeMatch:
    field: str
    address: str
    observed_domain: str
    observed_registrable_domain: str | None
    target_domain: str
    target_registrable_domain: str
    match_type: str
    confidence: str
    distance: int | None
    reasons: list[str]


@dataclass
class EvidenceLookalikeAnalysis:
    target_domain: str
    target_registrable_domain: str
    has_suspected_lookalikes: bool
    matches: list[EvidenceLookalikeMatch]
    summary: str


@dataclass
class EvidenceBundle:
    report_id: int
    subject: str | None
    ingest_source: str | None
    generated_at: datetime
    created_at: datetime | None
    received_at: datetime | None
    risk_score: int | None
    status: str
    disposition: str
    classification_code: str | None
    rationale_note: str | None
    resolved_at: datetime | None
    last_resolved_by: str | None
    campaign_id: int | None
    campaign_assignment_method: str | None
    campaign_assignment_score: float | None
    from_addr: str | None
    from_domain: str | None
    reply_to: list[str]
    return_path: str | None
    return_path_domain: str | None
    originating_ip: str | None
    message_id: str | None
    auth_summary: dict[str, Any]
    lookalike_analysis: EvidenceLookalikeAnalysis | None
    original_message: EvidenceOriginalMessage | None
    urls: list[str]
    url_domains: list[str]
    url_analysis: list[EvidenceUrl]
    attack_mapping: AttackMappingResult
    iocs: list[EvidenceIoc]
    flagged_artifacts: list[dict]
    attachments: list[EvidenceAttachment]
    resolution_history: list[EvidenceResolution]
    audit_trail: list[EvidenceAuditEvent]


@dataclass
class CampaignEvidenceReport:
    report_id: int
    subject: str | None
    from_addr: str | None
    status: str
    classification_code: str | None
    risk_score: int | None
    assignment_score: float | None
    created_at: datetime | None
    resolved_at: datetime | None
    last_resolved_by: str | None


@dataclass
class CampaignEvidenceResolution:
    report_id: int
    report_subject: str | None
    action: str
    disposition: str | None
    status_after: str
    classification_code: str | None
    note: str | None
    actor: str
    created_at: datetime | None


@dataclass
class CampaignEvidenceBundle:
    campaign_id: int
    campaign_key: str
    campaign_name: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    report_count: int
    is_locked: bool
    lock_reason: str | None
    algorithm_version: str
    generated_at: datetime
    disposition: str
    status_counts: dict[str, int]
    resolved_ratio: float
    classification_counts: list[tuple[str, int]]
    top_sender_addresses: list[tuple[str, int]]
    top_sender_domains: list[tuple[str, int]]
    top_url_domains: list[tuple[str, int]]
    top_attachment_hashes: list[tuple[str, int]]
    flagged_artifacts: list[tuple[str, str, int]]
    reports: list[CampaignEvidenceReport]
    resolution_history: list[CampaignEvidenceResolution]
    audit_trail: list[EvidenceAuditEvent]


def _fmt_utc(value: datetime | None) -> str:
    if value is None:
        return "-"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _md_escape(value: str | None) -> str:
    if value is None:
        return "-"
    return str(value).replace("|", r"\|")


def _safe_pdf_text(value: str | None) -> str:
    if not value:
        return "-"
    return value.encode("latin-1", "replace").decode("latin-1")


def extract_email_domain(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    if "@" not in cleaned:
        return None
    domain = cleaned.rsplit("@", 1)[-1].strip()
    return domain or None


def extract_url_domain(value: str | None) -> str | None:
    return resolve_url_domain(value)


def build_actor_label(
    *,
    actor_snapshot: str | None = None,
    actor_type: AuditActorType | str | None = None,
    actor_user_id: int | None = None,
    actor_api_key_id: int | None = None,
    user_lookup: dict[int, str] | None = None,
    api_key_lookup: dict[int, str] | None = None,
) -> str:
    if actor_user_id is not None and user_lookup and actor_user_id in user_lookup:
        return user_lookup[actor_user_id]

    if actor_api_key_id is not None and api_key_lookup and actor_api_key_id in api_key_lookup:
        return f"api-key:{api_key_lookup[actor_api_key_id]}"

    if actor_snapshot:
        return actor_snapshot

    kind = actor_type.value if isinstance(actor_type, AuditActorType) else (actor_type or "")
    if kind == AuditActorType.USER.value:
        return f"user:{actor_user_id}" if actor_user_id is not None else "user"
    if kind == AuditActorType.API_KEY.value:
        return f"api-key:{actor_api_key_id}" if actor_api_key_id is not None else "api-key"
    if kind == AuditActorType.LEGACY.value:
        return "legacy"
    if kind == AuditActorType.SYSTEM.value:
        return "system"
    return "unknown"


def _status_disposition(status: ReportStatus) -> str:
    if status == ReportStatus.PHISHING:
        return "MALICIOUS"
    if status == ReportStatus.BENIGN:
        return "SAFE"
    return "UNRESOLVED"


def _pdf_section_title(pdf: FPDF, title: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 14)
    pdf.multi_cell(0, 8, _safe_pdf_text(title))
    pdf.ln(1)


def _pdf_subsection_title(pdf: FPDF, title: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 11)
    pdf.multi_cell(0, 6, _safe_pdf_text(title))
    pdf.ln(1)


def _pdf_line(pdf: FPDF, text: str, *, bold: bool = False) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B" if bold else "", 10)
    pdf.multi_cell(0, 6, _safe_pdf_text(text))


def _pdf_kv_lines(rows: Iterable[tuple[str, str]]) -> list[str]:
    return [f"{label}: {value}" for label, value in rows]


def _pdf_kv_row(pdf: FPDF, label: str, value: str | None) -> None:
    pdf.set_x(pdf.l_margin)
    label_width = 50
    pdf.set_font("Helvetica", "B", 10)
    pdf.multi_cell(label_width, 6, _safe_pdf_text(label), new_x="RIGHT", new_y="TOP")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(pdf.epw - label_width, 6, _safe_pdf_text(value), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin)


def _pdf_bullets(pdf: FPDF, items: Iterable[str], *, empty_label: str = "-") -> None:
    rendered = [item for item in items if item]
    if not rendered:
        _pdf_line(pdf, empty_label)
        return
    for item in rendered:
        _pdf_line(pdf, f"- {item}")


def _attachment_type_label(item: EvidenceAttachment) -> str:
    filename = (item.filename or "").lower()
    if filename.endswith(".pkpass") or filename.endswith(".zip"):
        return "ZIP"
    if filename.endswith(".ics"):
        return "ICS"
    if filename.endswith(".pdf"):
        return "PDF"
    if filename.endswith(".docx"):
        return "DOCX"
    if filename.endswith(".xlsx"):
        return "XLSX"
    if filename.endswith(".pptx"):
        return "PPTX"
    if filename.endswith(".eml"):
        return "EML"
    if filename.endswith(".msg"):
        return "MSG"
    if item.content_type == "text/calendar":
        return "ICS"
    if item.content_type and "zip" in item.content_type.lower():
        return "ZIP"
    if item.content_type == "application/pdf":
        return "PDF"
    if item.filename and "." in item.filename:
        return item.filename.rsplit(".", 1)[-1].upper()
    return item.content_type or "-"


def _fmt_attachment_size(value: int | None) -> str:
    if value is None:
        return "-"
    if value < 1024:
        return f"{value} B"
    kb = value / 1024
    if kb < 1024:
        return f"{kb:.2f} KB"
    mb = kb / 1024
    return f"{mb:.2f} MB"


def _pdf_new_section_page(pdf: FPDF, title: str) -> None:
    if pdf.page_no() > 0:
        pdf.add_page()
    _pdf_section_title(pdf, title)


def _json_compatible(value: Any) -> Any:
    if isinstance(value, datetime):
        return _fmt_utc(value)
    if isinstance(value, list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, tuple):
        return [_json_compatible(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {
            key: _json_compatible(getattr(value, key))
            for key in value.__dataclass_fields__.keys()
        }
    return value


def _ioc_type_for_artifact(kind: str) -> str | None:
    mapping = {
        "FROM_ADDR": "email",
        "FROM_DOMAIN": "domain",
        "REPLY_TO": "email",
        "RETURN_PATH": "email",
        "RETURN_PATH_DOMAIN": "domain",
        "ORIGINATING_IP": "ip",
        "URL": "url",
        "URL_DOMAIN": "domain",
        "ATTACHMENT_NAME": "file_name",
        "ATTACHMENT_SHA256": "file_hash_sha256",
    }
    return mapping.get(kind)


def _normalize_ioc_value(ioc_type: str, value: str) -> str:
    cleaned = value.strip()
    if ioc_type in {"email", "domain", "file_hash_sha256"}:
        return cleaned.lower()
    return cleaned


def _build_iocs(bundle: EvidenceBundle) -> list[EvidenceIoc]:
    flagged_lookup: dict[tuple[str, str], list[str]] = {}
    for item in bundle.flagged_artifacts:
        kind = str(item.get("kind") or "")
        value = str(item.get("value") or "").strip()
        ioc_type = _ioc_type_for_artifact(kind)
        if not ioc_type or not value:
            continue
        key = (ioc_type, _normalize_ioc_value(ioc_type, value))
        flagged_lookup.setdefault(key, [])
        label = item.get("label")
        if label:
            label_text = str(label)
            if label_text not in flagged_lookup[key]:
                flagged_lookup[key].append(label_text)

    items: dict[tuple[str, str], EvidenceIoc] = {}

    def add_ioc(
        *,
        ioc_type: str,
        value: str | None,
        role: str,
        source: str,
        derived: bool = False,
    ) -> None:
        if not value:
            return
        normalized = _normalize_ioc_value(ioc_type, value)
        key = (ioc_type, normalized)
        flagged_labels = flagged_lookup.get(key, [])
        existing = items.get(key)
        if existing is None:
            existing = EvidenceIoc(
                type=ioc_type,
                value=normalized,
                roles=[],
                sources=[],
                derived=derived,
                flagged_malicious=bool(flagged_labels),
                flag_labels=list(flagged_labels),
            )
            items[key] = existing
        else:
            existing.derived = existing.derived and derived
            if flagged_labels:
                existing.flagged_malicious = True
                for label in flagged_labels:
                    if label not in existing.flag_labels:
                        existing.flag_labels.append(label)

        if role not in existing.roles:
            existing.roles.append(role)
        if source not in existing.sources:
            existing.sources.append(source)

    add_ioc(ioc_type="email", value=bundle.from_addr, role="from_addr", source="message.from_addr")
    add_ioc(ioc_type="domain", value=bundle.from_domain, role="from_domain", source="message.from_addr", derived=True)
    for reply_to in bundle.reply_to:
        add_ioc(ioc_type="email", value=reply_to, role="reply_to", source="message.reply_to")
        add_ioc(ioc_type="domain", value=extract_email_domain(reply_to), role="reply_to_domain", source="message.reply_to", derived=True)
    add_ioc(ioc_type="email", value=bundle.return_path, role="return_path", source="message.return_path")
    add_ioc(ioc_type="domain", value=bundle.return_path_domain, role="return_path_domain", source="message.return_path", derived=True)
    add_ioc(ioc_type="ip", value=bundle.originating_ip, role="originating_ip", source="message.originating_ip")

    if bundle.url_analysis:
        for index, item in enumerate(bundle.url_analysis, start=1):
            add_ioc(
                ioc_type="url",
                value=item.normalized_url or item.original_url,
                role="message_url",
                source=f"url_analysis[{index}]",
            )
            add_ioc(
                ioc_type="domain",
                value=item.initial_domain,
                role="message_url_domain",
                source=f"url_analysis[{index}]",
                derived=True,
            )
            if item.final_url and item.final_url != item.normalized_url:
                add_ioc(
                    ioc_type="url",
                    value=item.final_url,
                    role="resolved_url",
                    source=f"url_analysis[{index}]",
                    derived=True,
                )
            if item.final_domain:
                add_ioc(
                    ioc_type="domain",
                    value=item.final_domain,
                    role="resolved_url_domain",
                    source=f"url_analysis[{index}]",
                    derived=True,
                )
    else:
        for index, item in enumerate(bundle.urls, start=1):
            add_ioc(ioc_type="url", value=item, role="message_url", source=f"urls[{index}]")
            add_ioc(ioc_type="domain", value=extract_url_domain(item), role="message_url_domain", source=f"urls[{index}]", derived=True)

    for index, item in enumerate(bundle.attachments, start=1):
        add_ioc(ioc_type="file_name", value=item.filename, role="attachment_name", source=f"attachments[{index}]")
        add_ioc(ioc_type="file_hash_sha256", value=item.sha256, role="attachment_sha256", source=f"attachments[{index}]")

    return sorted(items.values(), key=lambda item: (item.type, item.value))


def _to_evidence_lookalike_analysis(payload: dict[str, Any] | None) -> EvidenceLookalikeAnalysis | None:
    if not payload:
        return None
    return EvidenceLookalikeAnalysis(
        target_domain=str(payload.get("target_domain") or ""),
        target_registrable_domain=str(payload.get("target_registrable_domain") or ""),
        has_suspected_lookalikes=bool(payload.get("has_suspected_lookalikes")),
        matches=[
            EvidenceLookalikeMatch(
                field=str(item.get("field") or ""),
                address=str(item.get("address") or ""),
                observed_domain=str(item.get("observed_domain") or ""),
                observed_registrable_domain=item.get("observed_registrable_domain"),
                target_domain=str(item.get("target_domain") or ""),
                target_registrable_domain=str(item.get("target_registrable_domain") or ""),
                match_type=str(item.get("match_type") or ""),
                confidence=str(item.get("confidence") or ""),
                distance=int(item["distance"]) if item.get("distance") is not None else None,
                reasons=[str(reason) for reason in (item.get("reasons") or []) if reason],
            )
            for item in (payload.get("matches") or [])
        ],
        summary=str(payload.get("summary") or ""),
    )


class EvidenceExportService:
    def __init__(self, db: Session):
        self.db = db

    def build_bundle(self, report: Report) -> EvidenceBundle:
        auth_summary = build_auth_summary(report)
        attachments = (
            self.db.execute(
                select(Attachment)
                .where(Attachment.report_id == report.id)
                .order_by(Attachment.created_at.asc(), Attachment.id.asc())
            )
            .scalars()
            .all()
        )
        resolutions = (
            self.db.execute(
                select(ReportResolution)
                .where(ReportResolution.report_id == report.id)
                .order_by(ReportResolution.created_at.asc(), ReportResolution.id.asc())
            )
            .scalars()
            .all()
        )
        audits = (
            self.db.execute(
                select(SecurityAuditEvent)
                .where(
                    SecurityAuditEvent.target_type == "report",
                    SecurityAuditEvent.target_id == str(report.id),
                )
                .order_by(SecurityAuditEvent.created_at.asc(), SecurityAuditEvent.id.asc())
            )
            .scalars()
            .all()
        )

        user_ids = {item.actor_user_id for item in resolutions if item.actor_user_id is not None}
        user_ids.update({item.actor_user_id for item in audits if item.actor_user_id is not None})
        api_key_ids = {item.actor_api_key_id for item in resolutions if item.actor_api_key_id is not None}
        api_key_ids.update({item.actor_api_key_id for item in audits if item.actor_api_key_id is not None})

        user_lookup: dict[int, str] = {}
        if user_ids:
            user_rows = self.db.execute(select(User.id, User.username).where(User.id.in_(user_ids))).all()
            user_lookup = {row[0]: row[1] for row in user_rows}

        api_key_lookup: dict[int, str] = {}
        if api_key_ids:
            key_rows = self.db.execute(select(ApiKey.id, ApiKey.name).where(ApiKey.id.in_(api_key_ids))).all()
            api_key_lookup = {row[0]: row[1] for row in key_rows}

        resolution_history = [
            EvidenceResolution(
                action=item.action.value,
                disposition=item.disposition.value if item.disposition else None,
                status_after=item.status_after.value,
                classification_code=item.classification_code,
                note=item.note,
                actor=build_actor_label(
                    actor_snapshot=item.actor,
                    actor_user_id=item.actor_user_id,
                    actor_api_key_id=item.actor_api_key_id,
                    user_lookup=user_lookup,
                    api_key_lookup=api_key_lookup,
                ),
                created_at=item.created_at,
            )
            for item in resolutions
        ]
        latest_resolve = next((item for item in reversed(resolutions) if item.action == ResolutionAction.RESOLVE), None)

        disposition = (
            latest_resolve.disposition.value
            if latest_resolve and latest_resolve.disposition
            else _status_disposition(report.status)
        )
        classification_code = report.classification_code or (latest_resolve.classification_code if latest_resolve else None)
        rationale_note = report.resolution_note or (latest_resolve.note if latest_resolve else None)

        audit_trail = [
            EvidenceAuditEvent(
                created_at=item.created_at,
                action=item.action,
                outcome=item.outcome,
                actor=build_actor_label(
                    actor_type=item.actor_type,
                    actor_user_id=item.actor_user_id,
                    actor_api_key_id=item.actor_api_key_id,
                    user_lookup=user_lookup,
                    api_key_lookup=api_key_lookup,
                ),
                request_id=item.request_id,
                event_uuid=item.event_uuid,
                event_hash=item.event_hash,
            )
            for item in audits
        ]

        urls = [item for item in (report.urls_json or []) if item]
        url_analysis_source = report.url_analysis_json or build_static_url_analysis(urls)
        url_analysis = [
            EvidenceUrl(
                original_url=str(item.get("original_url") or ""),
                normalized_url=str(item.get("normalized_url") or item.get("original_url") or ""),
                initial_domain=item.get("initial_domain"),
                final_url=item.get("final_url"),
                final_domain=item.get("final_domain"),
                redirect_count=int(item.get("redirect_count") or 0),
                is_shortener=bool(item.get("is_shortener")),
                used_redirector=bool(item.get("used_redirector")),
                domain_changed=bool(item.get("domain_changed")),
                suspicious_redirect=bool(item.get("suspicious_redirect")),
                resolution_status=str(item.get("resolution_status") or "disabled"),
                resolution_error=item.get("resolution_error"),
                redirect_chain=[
                    EvidenceUrlHop(
                        index=int(hop.get("index") or 0),
                        url=str(hop.get("url") or ""),
                        domain=hop.get("domain"),
                        status_code=int(hop["status_code"]) if hop.get("status_code") is not None else None,
                        location=hop.get("location"),
                    )
                    for hop in (item.get("redirect_chain") or [])
                ],
            )
            for item in url_analysis_source
        ]
        url_domains = sorted(
            {
                domain
                for domain in {
                    *(extract_url_domain(item) for item in urls),
                    *(item.final_domain for item in url_analysis if item.final_domain),
                }
                if domain
            }
        )
        attack_mapping = build_attack_mapping(
            AttackMappingInput(
                classification_code=classification_code,
                status=report.status.value,
                from_addr=report.from_addr,
                reply_to=list(report.reply_to or []),
                return_path=report.return_path,
                urls=urls,
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
                attachment_names=[item.filename for item in attachments if item.filename],
                auth_spf_result=str((auth_summary.get("spf") or {}).get("result") or "unknown"),
                auth_dkim_result=str((auth_summary.get("dkim") or {}).get("result") or "unknown"),
                auth_dmarc_result=str((auth_summary.get("dmarc") or {}).get("result") or "unknown"),
            )
        )
        lookalike_analysis = _to_evidence_lookalike_analysis(
            build_lookalike_analysis(
                mailbox_domain=report.mailbox_domain,
                from_addr=report.from_addr,
                reply_to=list(report.reply_to or []),
                return_path=report.return_path,
            )
        )

        bundle = EvidenceBundle(
            report_id=report.id,
            subject=report.subject,
            ingest_source=report.ingest_source.value if report.ingest_source else None,
            generated_at=datetime.now(timezone.utc),
            created_at=report.created_at,
            received_at=report.received_at or report.date,
            risk_score=report.risk_score,
            status=report.status.value,
            disposition=disposition,
            classification_code=classification_code,
            rationale_note=rationale_note,
            resolved_at=report.resolved_at,
            last_resolved_by=report.last_resolved_by,
            campaign_id=report.campaign_id,
            campaign_assignment_method=(
                report.campaign_assignment_method.value if report.campaign_assignment_method else None
            ),
            campaign_assignment_score=report.campaign_assignment_score,
            from_addr=report.from_addr,
            from_domain=extract_email_domain(report.from_addr),
            reply_to=list(report.reply_to or []),
            return_path=report.return_path,
            return_path_domain=extract_email_domain(report.return_path),
            originating_ip=report.originating_ip,
            message_id=report.message_id,
            auth_summary=auth_summary,
            lookalike_analysis=lookalike_analysis,
            original_message=(
                EvidenceOriginalMessage(
                    filename=report.original_filename,
                    content_type=report.original_content_type,
                    size_bytes=report.original_size_bytes,
                    sha256=report.original_sha256,
                    storage_key=report.original_s3_key,
                )
                if report.original_s3_key
                else None
            ),
            urls=urls,
            url_domains=url_domains,
            url_analysis=url_analysis,
            attack_mapping=attack_mapping,
            iocs=[],
            flagged_artifacts=list(report.flagged_artifacts_json or []),
            attachments=[
                EvidenceAttachment(
                    filename=item.filename,
                    content_type=item.content_type,
                    size_bytes=item.size_bytes,
                    sha256=item.sha256,
                    s3_key=item.s3_key,
                    created_at=item.created_at,
                )
                for item in attachments
            ],
            resolution_history=resolution_history,
            audit_trail=audit_trail,
        )
        bundle.iocs = _build_iocs(bundle)
        return bundle

    def render_markdown(self, bundle: EvidenceBundle) -> str:
        lines: list[str] = []
        lines.append("# Triagent Evidence Report")
        lines.append("")
        lines.append("## Report Identity")
        lines.append("")
        lines.append(f"- Case ID: `{bundle.report_id}`")
        lines.append(f"- Subject: {_md_escape(bundle.subject)}")
        lines.append(f"- Ingest Source: {_md_escape(bundle.ingest_source)}")
        lines.append(f"- Report Created (UTC): {_fmt_utc(bundle.created_at)}")
        lines.append(f"- Message Received (UTC): {_fmt_utc(bundle.received_at)}")
        lines.append(f"- Export Generated (UTC): {_fmt_utc(bundle.generated_at)}")
        lines.append("")
        lines.append("## Current Verdict and Rationale")
        lines.append("")
        lines.append(f"- Status: `{bundle.status}`")
        lines.append(f"- Disposition: `{bundle.disposition}`")
        lines.append(f"- Classification: `{_md_escape(bundle.classification_code)}`")
        lines.append(f"- Resolution Note: {_md_escape(bundle.rationale_note)}")
        lines.append(f"- Resolved At (UTC): {_fmt_utc(bundle.resolved_at)}")
        lines.append(f"- Last Resolved By: {_md_escape(bundle.last_resolved_by)}")
        lines.append("")
        lines.append("## ATT&CK Mapping")
        lines.append("")
        lines.append(f"- Matrix: {_md_escape(bundle.attack_mapping.matrix)}")
        lines.append(
            f"- Tactics: {_md_escape(', '.join(bundle.attack_mapping.tactics) if bundle.attack_mapping.tactics else None)}"
        )
        if bundle.attack_mapping.techniques:
            lines.append("- Techniques:")
            for item in bundle.attack_mapping.techniques:
                lines.append(
                    f"  - `{item.technique_id}` {_md_escape(item.technique_name)} (confidence: `{item.confidence}`)"
                )
                for rationale in item.rationales:
                    lines.append(f"    - {_md_escape(rationale)}")
        else:
            lines.append("- Techniques: -")
        if bundle.attack_mapping.context_codes:
            lines.append(
                f"- Context Codes: {_md_escape(', '.join(bundle.attack_mapping.context_codes))}"
            )
        if bundle.attack_mapping.notes:
            lines.append("- Notes:")
            for note in bundle.attack_mapping.notes:
                lines.append(f"  - {_md_escape(note)}")
        lines.append("")
        lines.append("## Artifacts")
        lines.append("")
        lines.append("### Messaging")
        lines.append("")
        lines.append(f"- From: {_md_escape(bundle.from_addr)}")
        lines.append(f"- From Domain: {_md_escape(bundle.from_domain)}")
        lines.append(f"- Reply-To: {_md_escape(', '.join(bundle.reply_to) if bundle.reply_to else None)}")
        lines.append(f"- Return-Path: {_md_escape(bundle.return_path)}")
        lines.append(f"- Return-Path Domain: {_md_escape(bundle.return_path_domain)}")
        lines.append(f"- Originating IP: {_md_escape(bundle.originating_ip)}")
        lines.append(f"- Message-ID: {_md_escape(bundle.message_id)}")
        lines.append("")
        lines.append("### Original Message")
        lines.append("")
        if bundle.original_message:
            lines.append(f"- Filename: {_md_escape(bundle.original_message.filename)}")
            lines.append(f"- Content Type: {_md_escape(bundle.original_message.content_type)}")
            lines.append(
                f"- Size (bytes): {_md_escape(str(bundle.original_message.size_bytes) if bundle.original_message.size_bytes is not None else None)}"
            )
            lines.append(f"- SHA-256: {_md_escape(bundle.original_message.sha256)}")
            lines.append(f"- Storage Key: {_md_escape(bundle.original_message.storage_key)}")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### Domain Lookalike Analysis")
        lines.append("")
        if bundle.lookalike_analysis:
            lines.append(f"- Target Domain: {_md_escape(bundle.lookalike_analysis.target_domain)}")
            lines.append(f"- Summary: {_md_escape(bundle.lookalike_analysis.summary)}")
            if bundle.lookalike_analysis.matches:
                lines.append("- Matches:")
                for item in bundle.lookalike_analysis.matches:
                    lines.append(
                        f"  - `{item.field}` {item.address} -> {item.observed_domain} "
                        f"(`{item.match_type}`, confidence: `{item.confidence}`)"
                    )
                    for reason in item.reasons:
                        lines.append(f"    - {_md_escape(reason)}")
            else:
                lines.append("- Matches: -")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### URLs")
        lines.append("")
        if bundle.urls:
            for item in bundle.urls:
                lines.append(f"- {_md_escape(item)}")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### URL Domains")
        lines.append("")
        if bundle.url_domains:
            for domain in bundle.url_domains:
                lines.append(f"- {_md_escape(domain)}")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### URL Resolution")
        lines.append("")
        if bundle.url_analysis:
            for index, item in enumerate(bundle.url_analysis, start=1):
                lines.append(f"#### URL {index}")
                lines.append("")
                lines.append(f"- Original URL: {_md_escape(item.original_url)}")
                lines.append(f"- Final URL: {_md_escape(item.final_url)}")
                lines.append(f"- Initial Domain: {_md_escape(item.initial_domain)}")
                lines.append(f"- Final Domain: {_md_escape(item.final_domain)}")
                lines.append(f"- Redirect Count: `{item.redirect_count}`")
                lines.append(f"- Resolution Status: `{_md_escape(item.resolution_status)}`")
                lines.append(f"- Shortener: `{'yes' if item.is_shortener else 'no'}`")
                lines.append(f"- Domain Changed: `{'yes' if item.domain_changed else 'no'}`")
                lines.append(f"- Suspicious Redirect: `{'yes' if item.suspicious_redirect else 'no'}`")
                if item.resolution_error:
                    lines.append(f"- Resolution Error: {_md_escape(item.resolution_error)}")
                if item.redirect_chain:
                    lines.append("- Redirect Chain:")
                    for hop in item.redirect_chain:
                        status_label = hop.status_code if hop.status_code is not None else "error"
                        target = f" -> {_md_escape(hop.location)}" if hop.location else ""
                        lines.append(
                            f"  - [{hop.index}] `{status_label}` {_md_escape(hop.url)}{target}"
                        )
                lines.append("")
        else:
            lines.append("- -")
            lines.append("")
        lines.append("### Attachments")
        lines.append("")
        lines.append("| Filename | Content Type | Size (bytes) | SHA-256 | Storage Key |")
        lines.append("| --- | --- | ---: | --- | --- |")
        if bundle.attachments:
            for item in bundle.attachments:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _md_escape(item.filename),
                            _md_escape(item.content_type),
                            _md_escape(str(item.size_bytes) if item.size_bytes is not None else None),
                            _md_escape(item.sha256),
                            _md_escape(item.s3_key),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("| - | - | - | - | - |")
        lines.append("")
        lines.append("### Flagged Artifacts")
        lines.append("")
        if bundle.flagged_artifacts:
            for item in bundle.flagged_artifacts:
                label = item.get("label") or "-"
                kind = item.get("kind") or "-"
                value = item.get("value") or "-"
                lines.append(f"- `{_md_escape(str(kind))}`: {_md_escape(str(value))} ({_md_escape(str(label))})")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("## Resolution History")
        lines.append("")
        lines.append("| Timestamp (UTC) | Action | Disposition | Status After | Classification | Actor | Note |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        if bundle.resolution_history:
            for item in bundle.resolution_history:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _fmt_utc(item.created_at),
                            _md_escape(item.action),
                            _md_escape(item.disposition),
                            _md_escape(item.status_after),
                            _md_escape(item.classification_code),
                            _md_escape(item.actor),
                            _md_escape(item.note),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("| - | - | - | - | - | - | - |")
        lines.append("")
        lines.append("## Case Audit Trail")
        lines.append("")
        lines.append("| Timestamp (UTC) | Action | Outcome | Actor | Request ID | Event UUID | Event Hash |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        if bundle.audit_trail:
            for item in bundle.audit_trail:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _fmt_utc(item.created_at),
                            _md_escape(item.action),
                            _md_escape(item.outcome),
                            _md_escape(item.actor),
                            _md_escape(item.request_id),
                            _md_escape(item.event_uuid),
                            _md_escape(item.event_hash),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("| - | - | - | - | - | - | - |")
        lines.append("")
        return "\n".join(lines)

    def render_pdf(self, bundle: EvidenceBundle) -> bytes:
        pdf = FPDF(format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        _pdf_section_title(pdf, "Triagent Evidence Report")

        _pdf_new_section_page(pdf, "Report Identity")
        for label, value in [
            ("Case ID", str(bundle.report_id)),
            ("Subject", bundle.subject),
            ("Ingest Source", bundle.ingest_source),
            ("Report Created (UTC)", _fmt_utc(bundle.created_at)),
            ("Message Received (UTC)", _fmt_utc(bundle.received_at)),
            ("Export Generated (UTC)", _fmt_utc(bundle.generated_at)),
        ]:
            _pdf_kv_row(pdf, label, value)

        _pdf_new_section_page(pdf, "Current Verdict and Rationale")
        for label, value in [
            ("Status", bundle.status),
            ("Disposition", bundle.disposition),
            ("Classification", bundle.classification_code),
            ("Resolution Note", bundle.rationale_note),
            ("Resolved At (UTC)", _fmt_utc(bundle.resolved_at)),
            ("Last Resolved By", bundle.last_resolved_by),
        ]:
            _pdf_kv_row(pdf, label, value)

        _pdf_new_section_page(pdf, "ATT&CK Mapping")
        _pdf_kv_row(pdf, "Matrix", bundle.attack_mapping.matrix)
        _pdf_kv_row(pdf, "Tactics", ", ".join(bundle.attack_mapping.tactics) if bundle.attack_mapping.tactics else "-")
        if bundle.attack_mapping.techniques:
            for item in bundle.attack_mapping.techniques:
                _pdf_subsection_title(pdf, f"{item.technique_id} - {item.technique_name}")
                _pdf_kv_row(pdf, "Confidence", item.confidence)
                _pdf_kv_row(pdf, "Reference", item.reference_url)
                if item.rationales:
                    _pdf_line(pdf, "Rationales")
                    for rationale in item.rationales:
                        _pdf_line(pdf, f"- {rationale}")
                pdf.ln(1)
        else:
            _pdf_line(pdf, "-")
        if bundle.attack_mapping.context_codes:
            _pdf_kv_row(pdf, "Context Codes", ", ".join(bundle.attack_mapping.context_codes))
        if bundle.attack_mapping.notes:
            _pdf_line(pdf, "Notes")
            for note in bundle.attack_mapping.notes:
                _pdf_line(pdf, f"- {note}")

        _pdf_new_section_page(pdf, "Artifacts")
        _pdf_subsection_title(pdf, "Messaging")
        for label, value in [
            ("From", bundle.from_addr),
            ("From Domain", bundle.from_domain),
            ("Reply-To", ", ".join(bundle.reply_to) if bundle.reply_to else "-"),
            ("Return-Path", bundle.return_path),
            ("Return-Path Domain", bundle.return_path_domain),
            ("Originating IP", bundle.originating_ip),
            ("Message-ID", bundle.message_id),
        ]:
            _pdf_kv_row(pdf, label, value)

        pdf.ln(1)
        _pdf_subsection_title(pdf, "Original Message")
        if bundle.original_message:
            for label, value in [
                ("Filename", bundle.original_message.filename),
                ("Content Type", bundle.original_message.content_type),
                ("Size", _fmt_attachment_size(bundle.original_message.size_bytes)),
                ("SHA-256", bundle.original_message.sha256),
                ("Storage Key", bundle.original_message.storage_key),
            ]:
                _pdf_kv_row(pdf, label, value)
        else:
            _pdf_line(pdf, "-")

        pdf.ln(1)
        _pdf_subsection_title(pdf, "Domain Lookalike Analysis")
        if bundle.lookalike_analysis:
            _pdf_kv_row(pdf, "Target Domain", bundle.lookalike_analysis.target_domain)
            _pdf_kv_row(pdf, "Summary", bundle.lookalike_analysis.summary)
            if bundle.lookalike_analysis.matches:
                for index, item in enumerate(bundle.lookalike_analysis.matches, start=1):
                    _pdf_subsection_title(pdf, f"Lookalike Match {index}")
                    for label, value in [
                        ("Field", item.field),
                        ("Address", item.address),
                        ("Observed Domain", item.observed_domain),
                        ("Observed Registrable Domain", item.observed_registrable_domain),
                        ("Match Type", item.match_type),
                        ("Confidence", item.confidence),
                        ("Distance", str(item.distance) if item.distance is not None else "-"),
                    ]:
                        _pdf_kv_row(pdf, label, value)
                    if item.reasons:
                        _pdf_line(pdf, "Reasons")
                        for reason in item.reasons:
                            _pdf_line(pdf, f"- {reason}")
                    pdf.ln(1)
            else:
                _pdf_line(pdf, "-")
        else:
            _pdf_line(pdf, "-")

        pdf.ln(1)
        _pdf_subsection_title(pdf, "URLs")
        _pdf_bullets(pdf, bundle.urls)

        pdf.ln(1)
        _pdf_subsection_title(pdf, "URL Domains")
        _pdf_bullets(pdf, bundle.url_domains)

        pdf.ln(1)
        _pdf_subsection_title(pdf, "URL Resolution")
        if bundle.url_analysis:
            for index, item in enumerate(bundle.url_analysis, start=1):
                _pdf_subsection_title(pdf, f"URL {index}")
                for label, value in [
                    ("Original URL", item.original_url),
                    ("Final URL", item.final_url),
                    ("Initial Domain", item.initial_domain),
                    ("Final Domain", item.final_domain),
                    ("Redirect Count", str(item.redirect_count)),
                    ("Resolution Status", item.resolution_status),
                    ("Shortener", "yes" if item.is_shortener else "no"),
                    ("Domain Changed", "yes" if item.domain_changed else "no"),
                    ("Suspicious Redirect", "yes" if item.suspicious_redirect else "no"),
                    ("Resolution Error", item.resolution_error),
                ]:
                    _pdf_kv_row(pdf, label, value)
                if item.redirect_chain:
                    _pdf_line(pdf, "Redirect Chain")
                    for hop in item.redirect_chain:
                        target = f" -> {hop.location}" if hop.location else ""
                        status_label = hop.status_code if hop.status_code is not None else "error"
                        _pdf_line(pdf, f"- [{hop.index}] {status_label} {hop.url}{target}")
                pdf.ln(1)
        else:
            _pdf_line(pdf, "-")

        pdf.ln(1)
        _pdf_subsection_title(pdf, "Attachments")
        if bundle.attachments:
            for index, item in enumerate(bundle.attachments, start=1):
                _pdf_subsection_title(pdf, f"Attachment {index}")
                for label, value in [
                    ("File name", item.filename),
                    ("File type", _attachment_type_label(item)),
                    ("File size", _fmt_attachment_size(item.size_bytes)),
                    ("SHA-256", item.sha256),
                    ("Stored At (UTC)", _fmt_utc(item.created_at)),
                ]:
                    _pdf_kv_row(pdf, label, value)
                pdf.ln(1)
        else:
            _pdf_line(pdf, "-")

        _pdf_subsection_title(pdf, "Flagged Artifacts")
        if bundle.flagged_artifacts:
            for item in bundle.flagged_artifacts:
                _pdf_line(pdf, f"- {item.get('label') or item.get('kind') or 'Artifact'}")
                _pdf_kv_row(pdf, "Kind", str(item.get("kind") or "-"))
                _pdf_kv_row(pdf, "Value", str(item.get("value") or "-"))
                pdf.ln(1)
        else:
            _pdf_line(pdf, "-")

        _pdf_new_section_page(pdf, "Resolution History")
        if bundle.resolution_history:
            for index, item in enumerate(bundle.resolution_history, start=1):
                _pdf_subsection_title(pdf, f"Event {index}")
                for label, value in [
                    ("Timestamp (UTC)", _fmt_utc(item.created_at)),
                    ("Action", item.action),
                    ("Disposition", item.disposition),
                    ("Status After", item.status_after),
                    ("Classification", item.classification_code),
                    ("Actor", item.actor),
                    ("Note", item.note),
                ]:
                    _pdf_kv_row(pdf, label, value)
                pdf.ln(1)
        else:
            _pdf_line(pdf, "-")

        _pdf_new_section_page(pdf, "Case Audit Trail")
        if bundle.audit_trail:
            for index, item in enumerate(bundle.audit_trail, start=1):
                _pdf_subsection_title(pdf, f"Audit Event {index}")
                for label, value in [
                    ("Timestamp (UTC)", _fmt_utc(item.created_at)),
                    ("Action", item.action),
                    ("Outcome", item.outcome),
                    ("Actor", item.actor),
                    ("Request ID", item.request_id),
                    ("Event UUID", item.event_uuid),
                    ("Event Hash", item.event_hash),
                ]:
                    _pdf_kv_row(pdf, label, value)
                pdf.ln(1)
        else:
            _pdf_line(pdf, "-")

        rendered = pdf.output()
        if isinstance(rendered, bytes):
            return rendered
        if isinstance(rendered, str):
            return rendered.encode("latin-1")
        return bytes(rendered)

    def build_report_json_document(self, bundle: EvidenceBundle) -> dict[str, Any]:
        return {
            "schema_version": "triagent.investigation_bundle.v1",
            "generated_at": _fmt_utc(bundle.generated_at),
            "report": {
                "id": bundle.report_id,
                "subject": bundle.subject,
                "ingest_source": bundle.ingest_source,
                "created_at": _fmt_utc(bundle.created_at),
                "received_at": _fmt_utc(bundle.received_at),
                "risk_score": bundle.risk_score,
                "status": bundle.status,
                "disposition": bundle.disposition,
                "classification_code": bundle.classification_code,
                "rationale_note": bundle.rationale_note,
                "resolved_at": _fmt_utc(bundle.resolved_at),
                "last_resolved_by": bundle.last_resolved_by,
                "campaign_id": bundle.campaign_id,
                "campaign_assignment_method": bundle.campaign_assignment_method,
                "campaign_assignment_score": bundle.campaign_assignment_score,
            },
            "message": {
                "from_addr": bundle.from_addr,
                "from_domain": bundle.from_domain,
                "reply_to": bundle.reply_to,
                "return_path": bundle.return_path,
                "return_path_domain": bundle.return_path_domain,
                "originating_ip": bundle.originating_ip,
                "message_id": bundle.message_id,
                "original_message": _json_compatible(bundle.original_message),
            },
            "authentication": _json_compatible(bundle.auth_summary),
            "lookalike_analysis": _json_compatible(bundle.lookalike_analysis),
            "attack_mapping": _json_compatible(bundle.attack_mapping),
            "artifacts": {
                "urls": bundle.urls,
                "url_domains": bundle.url_domains,
                "url_analysis": _json_compatible(bundle.url_analysis),
                "attachments": _json_compatible(bundle.attachments),
                "flagged_artifacts": _json_compatible(bundle.flagged_artifacts),
            },
            "iocs": _json_compatible(bundle.iocs),
            "resolution_history": _json_compatible(bundle.resolution_history),
            "audit_trail": _json_compatible(bundle.audit_trail),
        }

    def render_report_json(self, bundle: EvidenceBundle) -> bytes:
        payload = self.build_report_json_document(bundle)
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def build_ioc_document(self, bundle: EvidenceBundle) -> dict[str, Any]:
        return {
            "schema_version": "triagent.ioc_bundle.v1",
            "generated_at": _fmt_utc(bundle.generated_at),
            "report_id": bundle.report_id,
            "classification_code": bundle.classification_code,
            "disposition": bundle.disposition,
            "iocs": _json_compatible(bundle.iocs),
        }

    def render_ioc_json(self, bundle: EvidenceBundle) -> bytes:
        payload = self.build_ioc_document(bundle)
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def render_ioc_csv(self, bundle: EvidenceBundle) -> bytes:
        buffer = StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=[
                "type",
                "value",
                "roles",
                "sources",
                "derived",
                "flagged_malicious",
                "flag_labels",
            ],
        )
        writer.writeheader()
        for item in bundle.iocs:
            writer.writerow(
                {
                    "type": item.type,
                    "value": item.value,
                    "roles": ";".join(item.roles),
                    "sources": ";".join(item.sources),
                    "derived": "true" if item.derived else "false",
                    "flagged_malicious": "true" if item.flagged_malicious else "false",
                    "flag_labels": ";".join(item.flag_labels),
                }
            )
        return buffer.getvalue().encode("utf-8")

    @staticmethod
    def _campaign_disposition(status_counts: dict[str, int]) -> str:
        open_count = int(status_counts.get(ReportStatus.OPEN.value, 0))
        benign_count = int(status_counts.get(ReportStatus.BENIGN.value, 0))
        phishing_count = int(status_counts.get(ReportStatus.PHISHING.value, 0))
        total = open_count + benign_count + phishing_count
        if total == 0:
            return "UNASSIGNED"
        if phishing_count > 0 and benign_count == 0 and open_count == 0:
            return "MALICIOUS"
        if benign_count > 0 and phishing_count == 0 and open_count == 0:
            return "SAFE"
        if open_count > 0 and (benign_count > 0 or phishing_count > 0):
            return "PARTIALLY_RESOLVED"
        if open_count == total:
            return "OPEN"
        return "MIXED"

    @staticmethod
    def _top_counter(counter: Counter[str], limit: int = 20) -> list[tuple[str, int]]:
        return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]

    def build_campaign_bundle(self, campaign: Campaign) -> CampaignEvidenceBundle:
        reports = (
            self.db.execute(
                select(Report).where(Report.campaign_id == campaign.id).order_by(Report.created_at.asc(), Report.id.asc())
            )
            .scalars()
            .all()
        )
        report_ids = [item.id for item in reports]
        report_id_strings = [str(item) for item in report_ids]

        attachments: list[Attachment] = []
        if report_ids:
            attachments = (
                self.db.execute(
                    select(Attachment)
                    .join(Report, Report.id == Attachment.report_id)
                    .where(Report.campaign_id == campaign.id)
                    .order_by(Attachment.created_at.asc(), Attachment.id.asc())
                )
                .scalars()
                .all()
            )

        resolution_rows = []
        if report_ids:
            resolution_rows = self.db.execute(
                select(ReportResolution, Report.id, Report.subject)
                .join(Report, Report.id == ReportResolution.report_id)
                .where(Report.campaign_id == campaign.id)
                .order_by(ReportResolution.created_at.asc(), ReportResolution.id.asc())
            ).all()

        audit_clause = and_(
            SecurityAuditEvent.target_type == "campaign",
            SecurityAuditEvent.target_id == str(campaign.id),
        )
        if report_id_strings:
            audit_clause = or_(
                audit_clause,
                and_(
                    SecurityAuditEvent.target_type == "report",
                    SecurityAuditEvent.target_id.in_(report_id_strings),
                ),
            )
        audits = (
            self.db.execute(
                select(SecurityAuditEvent)
                .where(audit_clause)
                .order_by(SecurityAuditEvent.created_at.asc(), SecurityAuditEvent.id.asc())
            )
            .scalars()
            .all()
        )

        user_ids = {item.actor_user_id for item in audits if item.actor_user_id is not None}
        api_key_ids = {item.actor_api_key_id for item in audits if item.actor_api_key_id is not None}
        for resolution, _, _ in resolution_rows:
            if resolution.actor_user_id is not None:
                user_ids.add(resolution.actor_user_id)
            if resolution.actor_api_key_id is not None:
                api_key_ids.add(resolution.actor_api_key_id)

        user_lookup: dict[int, str] = {}
        if user_ids:
            user_rows = self.db.execute(select(User.id, User.username).where(User.id.in_(user_ids))).all()
            user_lookup = {row[0]: row[1] for row in user_rows}

        api_key_lookup: dict[int, str] = {}
        if api_key_ids:
            api_key_rows = self.db.execute(select(ApiKey.id, ApiKey.name).where(ApiKey.id.in_(api_key_ids))).all()
            api_key_lookup = {row[0]: row[1] for row in api_key_rows}

        status_counts = Counter[str]()
        classification_counter = Counter[str]()
        sender_address_counter = Counter[str]()
        sender_domain_counter = Counter[str]()
        url_domain_counter = Counter[str]()
        attachment_hash_counter = Counter[str]()
        flagged_counter = Counter[tuple[str, str]]()

        report_rows: list[CampaignEvidenceReport] = []
        for item in reports:
            status_counts[item.status.value] += 1
            if item.status in {ReportStatus.BENIGN, ReportStatus.PHISHING}:
                classification_counter[item.classification_code or "UNCLASSIFIED"] += 1
            sender = item.from_addr.strip().lower() if item.from_addr else None
            if sender:
                sender_address_counter[sender] += 1
                sender_domain = extract_email_domain(sender)
                if sender_domain:
                    sender_domain_counter[sender_domain] += 1
            for url in item.urls_json or []:
                domain = extract_url_domain(url)
                if domain:
                    url_domain_counter[domain] += 1
            for artifact in item.flagged_artifacts_json or []:
                kind = str(artifact.get("kind") or "-")
                value = str(artifact.get("value") or "-")
                flagged_counter[(kind, value)] += 1

            report_rows.append(
                CampaignEvidenceReport(
                    report_id=item.id,
                    subject=item.subject,
                    from_addr=item.from_addr,
                    status=item.status.value,
                    classification_code=item.classification_code,
                    risk_score=item.risk_score,
                    assignment_score=item.campaign_assignment_score,
                    created_at=item.created_at,
                    resolved_at=item.resolved_at,
                    last_resolved_by=item.last_resolved_by,
                )
            )

        for item in attachments:
            if item.sha256:
                attachment_hash_counter[item.sha256] += 1

        resolution_history = [
            CampaignEvidenceResolution(
                report_id=report_id,
                report_subject=report_subject,
                action=resolution.action.value,
                disposition=resolution.disposition.value if resolution.disposition else None,
                status_after=resolution.status_after.value,
                classification_code=resolution.classification_code,
                note=resolution.note,
                actor=build_actor_label(
                    actor_snapshot=resolution.actor,
                    actor_user_id=resolution.actor_user_id,
                    actor_api_key_id=resolution.actor_api_key_id,
                    user_lookup=user_lookup,
                    api_key_lookup=api_key_lookup,
                ),
                created_at=resolution.created_at,
            )
            for resolution, report_id, report_subject in resolution_rows
        ]

        audit_trail = [
            EvidenceAuditEvent(
                created_at=item.created_at,
                action=item.action,
                outcome=item.outcome,
                actor=build_actor_label(
                    actor_type=item.actor_type,
                    actor_user_id=item.actor_user_id,
                    actor_api_key_id=item.actor_api_key_id,
                    user_lookup=user_lookup,
                    api_key_lookup=api_key_lookup,
                ),
                request_id=item.request_id,
                event_uuid=item.event_uuid,
                event_hash=item.event_hash,
            )
            for item in audits
        ]

        report_count = len(reports)
        resolved_count = status_counts.get(ReportStatus.BENIGN.value, 0) + status_counts.get(ReportStatus.PHISHING.value, 0)
        resolved_ratio = (resolved_count / report_count) if report_count else 0.0

        return CampaignEvidenceBundle(
            campaign_id=campaign.id,
            campaign_key=campaign.campaign_key,
            campaign_name=campaign.name,
            first_seen=campaign.first_seen,
            last_seen=campaign.last_seen,
            report_count=report_count,
            is_locked=campaign.is_locked,
            lock_reason=campaign.lock_reason,
            algorithm_version=campaign.algorithm_version,
            generated_at=datetime.now(timezone.utc),
            disposition=self._campaign_disposition(dict(status_counts)),
            status_counts=dict(status_counts),
            resolved_ratio=resolved_ratio,
            classification_counts=self._top_counter(classification_counter, limit=50),
            top_sender_addresses=self._top_counter(sender_address_counter, limit=20),
            top_sender_domains=self._top_counter(sender_domain_counter, limit=20),
            top_url_domains=self._top_counter(url_domain_counter, limit=30),
            top_attachment_hashes=self._top_counter(attachment_hash_counter, limit=30),
            flagged_artifacts=[(kind, value, count) for (kind, value), count in sorted(flagged_counter.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))],
            reports=report_rows,
            resolution_history=resolution_history,
            audit_trail=audit_trail,
        )

    def render_campaign_markdown(self, bundle: CampaignEvidenceBundle) -> str:
        lines: list[str] = []
        lines.append("# Triagent Campaign Evidence Report")
        lines.append("")
        lines.append("## Campaign Identity")
        lines.append("")
        lines.append(f"- Campaign ID: `{bundle.campaign_id}`")
        lines.append(f"- Campaign Key: `{bundle.campaign_key}`")
        lines.append(f"- Campaign Name: {_md_escape(bundle.campaign_name)}")
        lines.append(f"- Reports: `{bundle.report_count}`")
        lines.append(f"- First Seen (UTC): {_fmt_utc(bundle.first_seen)}")
        lines.append(f"- Last Seen (UTC): {_fmt_utc(bundle.last_seen)}")
        lines.append(f"- Locked: `{bundle.is_locked}`")
        lines.append(f"- Lock Reason: {_md_escape(bundle.lock_reason)}")
        lines.append(f"- Algorithm Version: `{bundle.algorithm_version}`")
        lines.append(f"- Export Generated (UTC): {_fmt_utc(bundle.generated_at)}")
        lines.append("")

        open_count = bundle.status_counts.get(ReportStatus.OPEN.value, 0)
        benign_count = bundle.status_counts.get(ReportStatus.BENIGN.value, 0)
        phishing_count = bundle.status_counts.get(ReportStatus.PHISHING.value, 0)
        resolved_count = benign_count + phishing_count
        lines.append("## Resolution Summary")
        lines.append("")
        lines.append(f"- Campaign Disposition: `{bundle.disposition}`")
        lines.append(f"- Open Reports: `{open_count}`")
        lines.append(f"- Resolved Reports: `{resolved_count}`")
        lines.append(f"- Resolved Malicious (PHISHING): `{phishing_count}`")
        lines.append(f"- Resolved Safe (BENIGN): `{benign_count}`")
        lines.append(f"- Resolution Coverage: `{round(bundle.resolved_ratio * 100, 2)}%`")
        lines.append("")
        lines.append("### Classification Distribution")
        lines.append("")
        lines.append("| Classification | Count |")
        lines.append("| --- | ---: |")
        if bundle.classification_counts:
            for code, count in bundle.classification_counts:
                lines.append(f"| `{_md_escape(code)}` | {count} |")
        else:
            lines.append("| - | 0 |")
        lines.append("")

        lines.append("## Shared Artifacts")
        lines.append("")
        lines.append("### Top Sender Addresses")
        lines.append("")
        if bundle.top_sender_addresses:
            for value, count in bundle.top_sender_addresses:
                lines.append(f"- {_md_escape(value)} (`{count}`)")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### Top Sender Domains")
        lines.append("")
        if bundle.top_sender_domains:
            for value, count in bundle.top_sender_domains:
                lines.append(f"- {_md_escape(value)} (`{count}`)")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### Top URL Domains")
        lines.append("")
        if bundle.top_url_domains:
            for value, count in bundle.top_url_domains:
                lines.append(f"- {_md_escape(value)} (`{count}`)")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### Top Attachment Hashes (SHA-256)")
        lines.append("")
        if bundle.top_attachment_hashes:
            for value, count in bundle.top_attachment_hashes:
                lines.append(f"- `{_md_escape(value)}` (`{count}`)")
        else:
            lines.append("- -")
        lines.append("")
        lines.append("### Flagged Artifacts")
        lines.append("")
        lines.append("| Kind | Value | Count |")
        lines.append("| --- | --- | ---: |")
        if bundle.flagged_artifacts:
            for kind, value, count in bundle.flagged_artifacts:
                lines.append(f"| `{_md_escape(kind)}` | {_md_escape(value)} | {count} |")
        else:
            lines.append("| - | - | 0 |")
        lines.append("")

        lines.append("## Member Reports")
        lines.append("")
        lines.append("| Report ID | Status | Classification | From | Subject | Risk | Assign Score | Created (UTC) | Resolved (UTC) | Resolved By |")
        lines.append("| ---: | --- | --- | --- | --- | ---: | ---: | --- | --- | --- |")
        if bundle.reports:
            for item in bundle.reports:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            str(item.report_id),
                            _md_escape(item.status),
                            _md_escape(item.classification_code),
                            _md_escape(item.from_addr),
                            _md_escape(item.subject),
                            _md_escape(str(item.risk_score) if item.risk_score is not None else None),
                            _md_escape(
                                f"{item.assignment_score:.4f}" if item.assignment_score is not None else None
                            ),
                            _fmt_utc(item.created_at),
                            _fmt_utc(item.resolved_at),
                            _md_escape(item.last_resolved_by),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("| - | - | - | - | - | - | - | - | - | - |")
        lines.append("")

        lines.append("## Resolution History")
        lines.append("")
        lines.append("| Timestamp (UTC) | Report ID | Report Subject | Action | Disposition | Status After | Classification | Actor | Note |")
        lines.append("| --- | ---: | --- | --- | --- | --- | --- | --- | --- |")
        if bundle.resolution_history:
            for item in bundle.resolution_history:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _fmt_utc(item.created_at),
                            str(item.report_id),
                            _md_escape(item.report_subject),
                            _md_escape(item.action),
                            _md_escape(item.disposition),
                            _md_escape(item.status_after),
                            _md_escape(item.classification_code),
                            _md_escape(item.actor),
                            _md_escape(item.note),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("| - | - | - | - | - | - | - | - | - |")
        lines.append("")

        lines.append("## Campaign Audit Trail")
        lines.append("")
        lines.append("| Timestamp (UTC) | Action | Outcome | Actor | Request ID | Event UUID | Event Hash |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        if bundle.audit_trail:
            for item in bundle.audit_trail:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _fmt_utc(item.created_at),
                            _md_escape(item.action),
                            _md_escape(item.outcome),
                            _md_escape(item.actor),
                            _md_escape(item.request_id),
                            _md_escape(item.event_uuid),
                            _md_escape(item.event_hash),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("| - | - | - | - | - | - | - |")
        lines.append("")
        return "\n".join(lines)

    def render_campaign_pdf(self, bundle: CampaignEvidenceBundle) -> bytes:
        pdf = FPDF(format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        _pdf_section_title(pdf, "Triagent Campaign Evidence Report")
        _pdf_line(pdf, "")

        _pdf_section_title(pdf, "Campaign Identity")
        for line in _pdf_kv_lines(
            [
                ("Campaign ID", str(bundle.campaign_id)),
                ("Campaign Key", bundle.campaign_key),
                ("Campaign Name", bundle.campaign_name or "-"),
                ("Reports", str(bundle.report_count)),
                ("First Seen (UTC)", _fmt_utc(bundle.first_seen)),
                ("Last Seen (UTC)", _fmt_utc(bundle.last_seen)),
                ("Locked", str(bundle.is_locked)),
                ("Lock Reason", bundle.lock_reason or "-"),
                ("Algorithm Version", bundle.algorithm_version),
                ("Export Generated (UTC)", _fmt_utc(bundle.generated_at)),
            ]
        ):
            _pdf_line(pdf, line)

        open_count = bundle.status_counts.get(ReportStatus.OPEN.value, 0)
        benign_count = bundle.status_counts.get(ReportStatus.BENIGN.value, 0)
        phishing_count = bundle.status_counts.get(ReportStatus.PHISHING.value, 0)
        resolved_count = benign_count + phishing_count

        pdf.ln(2)
        _pdf_section_title(pdf, "Resolution Summary")
        for line in _pdf_kv_lines(
            [
                ("Campaign Disposition", bundle.disposition),
                ("Open Reports", str(open_count)),
                ("Resolved Reports", str(resolved_count)),
                ("Resolved Malicious (PHISHING)", str(phishing_count)),
                ("Resolved Safe (BENIGN)", str(benign_count)),
                ("Resolution Coverage", f"{round(bundle.resolved_ratio * 100, 2)}%"),
            ]
        ):
            _pdf_line(pdf, line)

        _pdf_line(pdf, "Classification Distribution", bold=True)
        if bundle.classification_counts:
            for code, count in bundle.classification_counts:
                _pdf_line(pdf, f"- {code}: {count}")
        else:
            _pdf_line(pdf, "-")

        pdf.ln(2)
        _pdf_section_title(pdf, "Shared Artifacts")
        _pdf_line(pdf, "Top Sender Addresses", bold=True)
        if bundle.top_sender_addresses:
            for value, count in bundle.top_sender_addresses:
                _pdf_line(pdf, f"- {value} ({count})")
        else:
            _pdf_line(pdf, "-")
        _pdf_line(pdf, "Top Sender Domains", bold=True)
        if bundle.top_sender_domains:
            for value, count in bundle.top_sender_domains:
                _pdf_line(pdf, f"- {value} ({count})")
        else:
            _pdf_line(pdf, "-")
        _pdf_line(pdf, "Top URL Domains", bold=True)
        if bundle.top_url_domains:
            for value, count in bundle.top_url_domains:
                _pdf_line(pdf, f"- {value} ({count})")
        else:
            _pdf_line(pdf, "-")
        _pdf_line(pdf, "Top Attachment Hashes (SHA-256)", bold=True)
        if bundle.top_attachment_hashes:
            for value, count in bundle.top_attachment_hashes:
                _pdf_line(pdf, f"- {value} ({count})")
        else:
            _pdf_line(pdf, "-")
        _pdf_line(pdf, "Flagged Artifacts", bold=True)
        if bundle.flagged_artifacts:
            for kind, value, count in bundle.flagged_artifacts:
                _pdf_line(pdf, f"- {kind}: {value} ({count})")
        else:
            _pdf_line(pdf, "-")

        pdf.ln(2)
        _pdf_section_title(pdf, "Member Reports")
        if bundle.reports:
            for item in bundle.reports:
                _pdf_line(
                    pdf,
                    (
                        f"- report={item.report_id} | status={item.status} | class={item.classification_code or '-'} | "
                        f"from={item.from_addr or '-'} | subject={item.subject or '-'} | risk={item.risk_score if item.risk_score is not None else '-'} | "
                        f"score={f'{item.assignment_score:.4f}' if item.assignment_score is not None else '-'} | "
                        f"created={_fmt_utc(item.created_at)} | resolved={_fmt_utc(item.resolved_at)} | by={item.last_resolved_by or '-'}"
                    ),
                )
        else:
            _pdf_line(pdf, "-")

        pdf.ln(2)
        _pdf_section_title(pdf, "Resolution History")
        if bundle.resolution_history:
            for item in bundle.resolution_history:
                _pdf_line(
                    pdf,
                    (
                        f"- {_fmt_utc(item.created_at)} | report={item.report_id} | action={item.action} | "
                        f"disposition={item.disposition or '-'} | status={item.status_after} | "
                        f"classification={item.classification_code or '-'} | actor={item.actor} | note={item.note or '-'}"
                    ),
                )
        else:
            _pdf_line(pdf, "-")

        pdf.ln(2)
        _pdf_section_title(pdf, "Campaign Audit Trail")
        if bundle.audit_trail:
            for item in bundle.audit_trail:
                _pdf_line(
                    pdf,
                    (
                        f"- {_fmt_utc(item.created_at)} | action={item.action} | outcome={item.outcome} | "
                        f"actor={item.actor} | request_id={item.request_id or '-'} | "
                        f"event_uuid={item.event_uuid} | hash={item.event_hash}"
                    ),
                )
        else:
            _pdf_line(pdf, "-")

        rendered = pdf.output()
        if isinstance(rendered, bytes):
            return rendered
        if isinstance(rendered, str):
            return rendered.encode("latin-1")
        return bytes(rendered)

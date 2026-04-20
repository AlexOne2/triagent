from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any

from app.models.report import ArtifactKind, ResolutionDisposition


SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".7z",
    ".docm",
    ".exe",
    ".hta",
    ".htm",
    ".html",
    ".img",
    ".iso",
    ".js",
    ".lnk",
    ".rar",
    ".scr",
    ".vbs",
    ".xlsm",
    ".zip",
}
AUTH_FAIL_RESULTS = {"fail", "softfail", "permerror", "temperror"}
CREDENTIAL_KEYWORDS = {
    "account",
    "credential",
    "login",
    "mailbox",
    "mfa",
    "office 365",
    "password",
    "reauthenticate",
    "reset",
    "sign in",
    "verify",
}
FINANCE_KEYWORDS = {"bank", "invoice", "payment", "remittance", "transfer", "urgent wire", "wire"}


@dataclass(frozen=True)
class AssistArtifactOption:
    kind: ArtifactKind
    value: str
    label: str


@dataclass
class ReportAssistInput:
    report_id: int
    risk_score: int
    status: str
    subject: str | None = None
    body_excerpt: str | None = None
    from_addr: str | None = None
    from_display_name: str | None = None
    reply_to: list[str] = field(default_factory=list)
    return_path: str | None = None
    mailbox_domain: str | None = None
    in_reply_to: str | None = None
    urls: list[str] = field(default_factory=list)
    url_analysis: list[dict[str, Any]] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    auth_summary: dict[str, Any] = field(default_factory=dict)
    lookalike_analysis: dict[str, Any] | None = None
    attack_mapping: dict[str, Any] | None = None
    artifact_options: list[AssistArtifactOption] = field(default_factory=list)


@dataclass
class ReportAssistArtifactDraft:
    kind: ArtifactKind
    value: str
    label: str
    rationale: str | None = None


@dataclass
class ReportAssistDraftResult:
    provider: str
    model: str
    generated_at: datetime
    recommended_disposition: ResolutionDisposition
    recommended_classification_code: str | None
    confidence: str
    summary: str
    recommended_note: str
    reasons: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    review_warnings: list[str] = field(default_factory=list)
    flagged_artifacts: list[ReportAssistArtifactDraft] = field(default_factory=list)


def build_report_assist_draft(
    report_input: ReportAssistInput,
) -> ReportAssistDraftResult:
    return _build_heuristic_draft(report_input)


def _build_heuristic_draft(report_input: ReportAssistInput) -> ReportAssistDraftResult:
    reasons: list[str] = []
    missing_evidence: list[str] = []
    review_warnings: list[str] = ["Assist draft generated from local evidence. Analyst approval is required before resolving the report."]
    flagged_artifacts: list[ReportAssistArtifactDraft] = []

    text_blob = " ".join(
        item
        for item in [
            report_input.subject or "",
            report_input.from_display_name or "",
            report_input.body_excerpt or "",
        ]
        if item
    ).lower()
    suspicious_redirects = [
        item
        for item in report_input.url_analysis
        if item.get("suspicious_redirect") or item.get("domain_changed") or item.get("is_shortener")
    ]
    suspicious_attachments = [
        name for name in report_input.attachment_names if _has_suspicious_attachment_extension(name)
    ]
    lookalike_matches = list((report_input.lookalike_analysis or {}).get("matches") or [])
    auth_summary = report_input.auth_summary or {}
    auth_failures = [
        name.upper()
        for name in ("spf", "dkim", "dmarc")
        if str(((auth_summary.get(name) or {}).get("result") or "unknown")).lower() in AUTH_FAIL_RESULTS
    ]
    mismatch_signals = _sender_mismatch_signals(report_input)
    credential_theme = any(keyword in text_blob for keyword in CREDENTIAL_KEYWORDS)
    finance_theme = any(keyword in text_blob for keyword in FINANCE_KEYWORDS)
    has_links = bool(report_input.urls or report_input.url_analysis)
    thread_signal = bool(report_input.in_reply_to) or (report_input.subject or "").lower().startswith("re:")
    has_attack_mapping = bool((report_input.attack_mapping or {}).get("techniques"))

    classification_code: str | None = None
    disposition = ResolutionDisposition.SAFE

    if suspicious_attachments:
        disposition = ResolutionDisposition.MALICIOUS
        classification_code = "MAL_ATTACH"
        reasons.append(
            f"Attachment workflow shows suspicious file types ({', '.join(sorted(set(suspicious_attachments))[:3])})."
        )
        for name in suspicious_attachments[:2]:
            _append_artifact(
                flagged_artifacts,
                _artifact_option(report_input, ArtifactKind.ATTACHMENT_NAME, name),
                "Suspicious attachment file name.",
            )
        for name in suspicious_attachments[:2]:
            attachment_hash = _attachment_hash_for_name(report_input, name)
            if attachment_hash:
                _append_artifact(
                    flagged_artifacts,
                    _artifact_option(report_input, ArtifactKind.ATTACHMENT_SHA256, attachment_hash),
                    "Attachment hash for downstream blocking or sandboxing.",
                )

    elif thread_signal and (has_links or report_input.attachment_names):
        disposition = ResolutionDisposition.MALICIOUS
        classification_code = "THREAD_HIJACK"
        reasons.append("Message looks like a reply-chain continuation while introducing a new payload.")

    elif finance_theme and (mismatch_signals or lookalike_matches):
        disposition = ResolutionDisposition.MALICIOUS
        classification_code = "FIN_FRAUD"
        reasons.append("Payment or invoice language appears alongside impersonation or sender-mismatch signals.")

    elif credential_theme and has_links:
        disposition = ResolutionDisposition.MALICIOUS
        classification_code = "CRED_HARV"
        reasons.append("Credential-themed language appears together with URLs that require analyst review.")

    elif lookalike_matches:
        disposition = ResolutionDisposition.MALICIOUS
        classification_code = "IMPER" if not auth_failures else "SPOOF"
        highest_match = max(
            (item.get("confidence") for item in lookalike_matches),
            default="medium",
            key=lambda value: {"low": 1, "medium": 2, "high": 3}.get(str(value), 1),
        )
        reasons.append(
            f"Sender-domain lookalike detection found {len(lookalike_matches)} suspected impersonation signal(s), strongest confidence {highest_match}."
        )

    elif auth_failures and mismatch_signals:
        disposition = ResolutionDisposition.MALICIOUS
        classification_code = "SPOOF"
        reasons.append(
            f"Sender-authentication failures ({', '.join(auth_failures)}) appear alongside routing-domain mismatch signals."
        )

    elif suspicious_redirects or (has_links and report_input.risk_score >= 60):
        disposition = ResolutionDisposition.MALICIOUS
        classification_code = "MAL_URL"
        if suspicious_redirects:
            reasons.append("URL analysis shows redirect or domain-change behavior consistent with link-based phishing.")
        else:
            reasons.append("URL-bearing message has elevated risk and should be resolved as link-driven phishing pending analyst review.")

    elif (
        report_input.risk_score <= 25
        and not has_links
        and not suspicious_attachments
        and not lookalike_matches
        and not auth_failures
        and not mismatch_signals
    ):
        disposition = ResolutionDisposition.SAFE
        reasons.append("No suspicious link, attachment, impersonation, or authentication signals were observed.")

    elif not has_attack_mapping and report_input.risk_score < 45:
        disposition = ResolutionDisposition.SAFE
        reasons.append("Observed signals are weak and do not currently support a malicious phishing classification.")

    else:
        disposition = ResolutionDisposition.MALICIOUS if report_input.risk_score >= 60 else ResolutionDisposition.SAFE
        if disposition == ResolutionDisposition.MALICIOUS:
            classification_code = "MAL_URL" if has_links else "SPOOF"
            reasons.append("Risk score and available evidence suggest a suspicious message, but analyst confirmation is still required.")
        else:
            reasons.append("Evidence is inconclusive; safe verdict is a low-confidence draft only.")

    _add_sender_artifacts(report_input, flagged_artifacts, classification_code, mismatch_signals, lookalike_matches)
    _add_url_artifacts(report_input, flagged_artifacts, classification_code, suspicious_redirects)

    if disposition == ResolutionDisposition.MALICIOUS and classification_code is None:
        classification_code = "MAL_URL" if has_links else "SPOOF"

    confidence = _draft_confidence(
        disposition=disposition,
        risk_score=report_input.risk_score,
        suspicious_redirects=bool(suspicious_redirects),
        suspicious_attachments=bool(suspicious_attachments),
        lookalike_matches=lookalike_matches,
        auth_failures=auth_failures,
        mismatch_signals=mismatch_signals,
    )

    if disposition == ResolutionDisposition.MALICIOUS and has_links and not suspicious_redirects:
        missing_evidence.append("No redirect-chain evidence confirms a malicious final landing page.")
    if disposition == ResolutionDisposition.MALICIOUS and not auth_failures and not lookalike_matches:
        missing_evidence.append("Sender-identity evidence is limited; reviewer should confirm context from content and artifacts.")
    if disposition == ResolutionDisposition.MALICIOUS and not flagged_artifacts:
        missing_evidence.append("No concrete artifact was selected automatically; reviewer should choose the strongest indicator before closing.")
    if confidence == "low":
        review_warnings.append("Low-confidence draft. Review classification, flagged artifacts, and note before closing.")

    summary = _build_summary(disposition, classification_code, confidence, reasons)
    recommended_note = _build_recommended_note(
        disposition=disposition,
        classification_code=classification_code,
        reasons=reasons,
        flagged_artifacts=flagged_artifacts,
        missing_evidence=missing_evidence,
    )
    return ReportAssistDraftResult(
        provider="local",
        model="heuristic-v1",
        generated_at=datetime.now(timezone.utc),
        recommended_disposition=disposition,
        recommended_classification_code=classification_code if disposition == ResolutionDisposition.MALICIOUS else None,
        confidence=confidence,
        summary=summary,
        recommended_note=recommended_note,
        reasons=reasons[:4],
        missing_evidence=missing_evidence[:3],
        review_warnings=review_warnings[:3],
        flagged_artifacts=flagged_artifacts[:6],
    )


def _sender_mismatch_signals(report_input: ReportAssistInput) -> list[str]:
    from_domain = _email_domain(report_input.from_addr)
    signals: list[str] = []
    for reply_to in report_input.reply_to:
        reply_domain = _email_domain(reply_to)
        if from_domain and reply_domain and reply_domain != from_domain:
            signals.append(f"reply_to:{reply_domain}")
    return_path_domain = _email_domain(report_input.return_path)
    if from_domain and return_path_domain and return_path_domain != from_domain:
        signals.append(f"return_path:{return_path_domain}")
    return signals


def _add_sender_artifacts(
    report_input: ReportAssistInput,
    flagged_artifacts: list[ReportAssistArtifactDraft],
    classification_code: str | None,
    mismatch_signals: list[str],
    lookalike_matches: list[dict[str, Any]],
) -> None:
    if classification_code not in {"SPOOF", "IMPER", "FIN_FRAUD"}:
        return
    if report_input.from_addr:
        _append_artifact(
            flagged_artifacts,
            _artifact_option(report_input, ArtifactKind.FROM_ADDR, report_input.from_addr),
            "Primary sender identity used in the message.",
        )
    from_domain = _email_domain(report_input.from_addr)
    if from_domain:
        _append_artifact(
            flagged_artifacts,
            _artifact_option(report_input, ArtifactKind.FROM_DOMAIN, from_domain),
            "Observed sender domain associated with the impersonation signal.",
        )
    if mismatch_signals and report_input.return_path:
        _append_artifact(
            flagged_artifacts,
            _artifact_option(report_input, ArtifactKind.RETURN_PATH, report_input.return_path),
            "Return-Path differs from the visible sender identity.",
        )
    for reply_to in report_input.reply_to[:1]:
        _append_artifact(
            flagged_artifacts,
            _artifact_option(report_input, ArtifactKind.REPLY_TO, reply_to),
            "Reply-To address routes responses away from the visible sender.",
        )
    if lookalike_matches:
        observed_domain = str(lookalike_matches[0].get("observed_domain") or "").strip().lower()
        if observed_domain:
            _append_artifact(
                flagged_artifacts,
                _artifact_option(report_input, ArtifactKind.FROM_DOMAIN, observed_domain),
                "Domain involved in same-org impersonation or lookalike behavior.",
            )


def _add_url_artifacts(
    report_input: ReportAssistInput,
    flagged_artifacts: list[ReportAssistArtifactDraft],
    classification_code: str | None,
    suspicious_redirects: list[dict[str, Any]],
) -> None:
    if classification_code not in {"CRED_HARV", "MAL_URL", "THREAD_HIJACK", "FIN_FRAUD"}:
        return
    if suspicious_redirects:
        for item in suspicious_redirects[:2]:
            final_url = str(item.get("final_url") or "").strip()
            final_domain = str(item.get("final_domain") or "").strip().lower()
            original_url = str(item.get("original_url") or "").strip()
            if final_domain:
                _append_artifact(
                    flagged_artifacts,
                    _artifact_option(report_input, ArtifactKind.URL_DOMAIN, final_domain),
                    "Resolved landing domain linked to the suspicious redirect chain.",
                )
            if final_url:
                _append_artifact(
                    flagged_artifacts,
                    _artifact_option(report_input, ArtifactKind.URL, final_url),
                    "Resolved landing URL that the analyst should review or block.",
                )
            if original_url:
                _append_artifact(
                    flagged_artifacts,
                    _artifact_option(report_input, ArtifactKind.URL, original_url),
                    "Original URL observed in the reported message.",
                )
        return
    for url in report_input.urls[:1]:
        _append_artifact(
            flagged_artifacts,
            _artifact_option(report_input, ArtifactKind.URL, url),
            "Message URL used in the reported mail.",
        )
        domain = _url_domain(url)
        if domain:
            _append_artifact(
                flagged_artifacts,
                _artifact_option(report_input, ArtifactKind.URL_DOMAIN, domain),
                "Domain extracted from the observed message URL.",
            )


def _attachment_hash_for_name(report_input: ReportAssistInput, name: str) -> str | None:
    lower_name = name.strip().lower()
    for option in report_input.artifact_options:
        if option.kind != ArtifactKind.ATTACHMENT_NAME or option.value.strip().lower() != lower_name:
            continue
        for maybe_hash in report_input.artifact_options:
            if maybe_hash.kind == ArtifactKind.ATTACHMENT_SHA256:
                return maybe_hash.value
    return None


def _draft_confidence(
    *,
    disposition: ResolutionDisposition,
    risk_score: int,
    suspicious_redirects: bool,
    suspicious_attachments: bool,
    lookalike_matches: list[dict[str, Any]],
    auth_failures: list[str],
    mismatch_signals: list[str],
) -> str:
    strong_signals = int(suspicious_redirects) + int(suspicious_attachments) + int(any(item.get("confidence") == "high" for item in lookalike_matches))
    strong_signals += int(len(auth_failures) >= 2 and bool(mismatch_signals))
    if disposition == ResolutionDisposition.MALICIOUS:
        if strong_signals >= 2 or (strong_signals >= 1 and risk_score >= 70):
            return "high"
        if strong_signals >= 1 or risk_score >= 55 or len(auth_failures) >= 1:
            return "medium"
        return "low"
    if risk_score <= 20 and not suspicious_redirects and not suspicious_attachments and not lookalike_matches and not auth_failures:
        return "high"
    if risk_score <= 35 and not suspicious_attachments and not lookalike_matches:
        return "medium"
    return "low"


def _build_summary(
    disposition: ResolutionDisposition,
    classification_code: str | None,
    confidence: str,
    reasons: list[str],
) -> str:
    action = "malicious" if disposition == ResolutionDisposition.MALICIOUS else "safe"
    label = f"{action} / {classification_code}" if classification_code else action
    if reasons:
        return f"Recommend resolving as {label} ({confidence} confidence). {reasons[0]}"
    return f"Recommend resolving as {label} ({confidence} confidence)."


def _build_recommended_note(
    *,
    disposition: ResolutionDisposition,
    classification_code: str | None,
    reasons: list[str],
    flagged_artifacts: list[ReportAssistArtifactDraft],
    missing_evidence: list[str],
) -> str:
    parts = [
        f"Assist draft recommends resolving as {disposition.value}{f' / {classification_code}' if classification_code else ''}.",
    ]
    if reasons:
        parts.append(f"Key evidence: {' '.join(reasons[:3])}")
    if flagged_artifacts:
        parts.append(
            "Suggested flagged artifacts: "
            + ", ".join(item.label or f"{item.kind.value} {item.value}" for item in flagged_artifacts[:4])
            + "."
        )
    if missing_evidence:
        parts.append(f"Reviewer checks before close: {' '.join(missing_evidence[:2])}")
    return " ".join(parts)

def _artifact_option(
    report_input: ReportAssistInput,
    kind: ArtifactKind,
    value: str,
) -> AssistArtifactOption | None:
    normalized = value.strip().lower() if kind in {ArtifactKind.URL_DOMAIN, ArtifactKind.ATTACHMENT_SHA256, ArtifactKind.FROM_DOMAIN, ArtifactKind.RETURN_PATH_DOMAIN} else value.strip()
    for item in report_input.artifact_options:
        item_value = item.value.strip().lower() if item.kind in {ArtifactKind.URL_DOMAIN, ArtifactKind.ATTACHMENT_SHA256, ArtifactKind.FROM_DOMAIN, ArtifactKind.RETURN_PATH_DOMAIN} else item.value.strip()
        if item.kind == kind and item_value == normalized:
            return item
    return None


def _append_artifact(
    flagged_artifacts: list[ReportAssistArtifactDraft],
    option: AssistArtifactOption | None,
    rationale: str | None,
) -> None:
    if option is None:
        return
    if any(item.kind == option.kind and item.value == option.value for item in flagged_artifacts):
        return
    flagged_artifacts.append(
        ReportAssistArtifactDraft(
            kind=option.kind,
            value=option.value,
            label=option.label,
            rationale=rationale,
        )
    )


def _email_domain(value: str | None) -> str | None:
    if not value:
        return None
    addr = parseaddr(value)[1] or value
    cleaned = addr.strip().strip("<>").lower()
    if "@" not in cleaned:
        return None
    return cleaned.rsplit("@", 1)[-1] or None


def _url_domain(value: str | None) -> str | None:
    if not value:
        return None
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#:]+)", value.strip())
    if not match:
        return None
    return match.group(1).lower()


def _has_suspicious_attachment_extension(name: str) -> bool:
    lowered = name.strip().lower()
    return any(lowered.endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS)

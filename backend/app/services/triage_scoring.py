from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Any

from app.services.analysis import normalize_subject, normalize_text, strip_html


TRIAGE_SCORING_VERSION = "v1"

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
FINANCE_KEYWORDS = {
    "accounts payable",
    "bank",
    "invoice",
    "payment",
    "remittance",
    "routing number",
    "transfer",
    "urgent wire",
    "wire",
}
MARKETING_KEYWORDS = {
    "deal",
    "discount",
    "limited time",
    "manage preferences",
    "newsletter",
    "offer",
    "promo",
    "sale",
    "special offer",
    "unsubscribe",
    "view in browser",
}
BENIGN_TRANSACTIONAL_KEYWORDS = {
    "calendar",
    "invitation",
    "it notice",
    "meeting",
    "receipt",
    "reservation",
    "shipment",
    "support case",
    "ticket update",
    "tracking",
}
HEADER_LIST_INDICATORS = {"list-id", "list-unsubscribe", "list-unsubscribe-post", "list-help", "list-post"}
BULK_PRECEDENCE_VALUES = {"bulk", "list", "junk"}
LOOKALIKE_CONFIDENCE_WEIGHT = {"low": 12, "medium": 22, "high": 32}
LOOKALIKE_INVESTIGATION_WEIGHT = {"low": 8, "medium": 18, "high": 28}


@dataclass
class ReportTriageInput:
    risk_score: int
    subject: str | None = None
    body_text: str | None = None
    body_html: str | None = None
    from_addr: str | None = None
    from_display_name: str | None = None
    reply_to: list[str] = field(default_factory=list)
    return_path: str | None = None
    mailbox_domain: str | None = None
    in_reply_to: str | None = None
    urls: list[str] = field(default_factory=list)
    url_analysis: list[dict[str, Any]] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    headers_json: dict[str, Any] = field(default_factory=dict)
    auth_summary: dict[str, Any] = field(default_factory=dict)
    lookalike_analysis: dict[str, Any] | None = None


@dataclass
class ReportTriageAssessmentResult:
    threat_score: int
    bulk_benign_score: int
    investigation_priority_score: int
    automation_confidence_score: int
    bucket: str
    analyst_worthy: bool
    summary: str
    reason_codes: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def build_report_triage_assessment_for_report(
    report: Any,
    *,
    attachment_names: list[str] | None = None,
    auth_summary: dict[str, Any] | None = None,
    raw_lookalike_analysis: dict[str, Any] | None = None,
    raw_url_analysis: list[dict[str, Any]] | None = None,
) -> ReportTriageAssessmentResult:
    from app.services.auth_summary import build_auth_summary
    from app.services.lookalike_detection import build_lookalike_analysis
    from app.services.url_resolution import build_static_url_analysis

    resolved_auth_summary = auth_summary or build_auth_summary(report)
    resolved_url_analysis = raw_url_analysis or report.url_analysis_json or build_static_url_analysis(report.urls_json or [])
    resolved_lookalike_analysis = raw_lookalike_analysis or build_lookalike_analysis(
        mailbox_domain=report.mailbox_domain,
        from_addr=report.from_addr,
        reply_to=list(report.reply_to or []),
        return_path=report.return_path,
    )
    return build_report_triage_assessment(
        ReportTriageInput(
            risk_score=report.risk_score,
            subject=report.subject,
            body_text=report.body_text,
            body_html=report.body_html,
            from_addr=report.from_addr,
            from_display_name=report.from_display_name,
            reply_to=list(report.reply_to or []),
            return_path=report.return_path,
            mailbox_domain=report.mailbox_domain,
            in_reply_to=report.in_reply_to,
            urls=[item for item in (report.urls_json or []) if item],
            url_analysis=resolved_url_analysis,
            attachment_names=attachment_names or [item.filename for item in report.attachments if item.filename],
            headers_json=report.headers_json or {},
            auth_summary=resolved_auth_summary,
            lookalike_analysis=resolved_lookalike_analysis,
        )
    )


def build_report_triage_assessment(report_input: ReportTriageInput) -> ReportTriageAssessmentResult:
    threat_score = 0
    bulk_benign_score = 0
    investigation_priority_score = 0
    automation_confidence_score = 35
    analyst_worthy = False
    strong_threat_signals = 0
    strong_bulk_signals = 0
    reason_codes: list[str] = []
    reasons: list[str] = []

    def add_reason(code: str, text: str) -> None:
        if code in reason_codes:
            return
        reason_codes.append(code)
        reasons.append(text)

    text_blob = _build_text_blob(report_input)
    normalized_subject = normalize_subject(report_input.subject)
    headers = _normalize_headers(report_input.headers_json)
    lookalike_matches = list((report_input.lookalike_analysis or {}).get("matches") or [])
    suspicious_redirects = [
        item
        for item in report_input.url_analysis
        if item.get("suspicious_redirect")
    ]
    suspicious_attachments = [
        name for name in report_input.attachment_names if _has_suspicious_attachment_extension(name)
    ]
    auth_failures = [
        name.upper()
        for name in ("spf", "dkim", "dmarc")
        if str(((report_input.auth_summary.get(name) or {}).get("result") or "unknown")).lower() in AUTH_FAIL_RESULTS
    ]
    auth_all_pass = all(
        str(((report_input.auth_summary.get(name) or {}).get("result") or "unknown")).lower() == "pass"
        for name in ("spf", "dkim", "dmarc")
    )
    mismatch_signals = _sender_mismatch_signals(report_input)
    credential_theme = any(keyword in text_blob for keyword in CREDENTIAL_KEYWORDS)
    finance_theme = any(keyword in text_blob for keyword in FINANCE_KEYWORDS)
    marketing_theme = any(keyword in text_blob for keyword in MARKETING_KEYWORDS)
    benign_transactional_theme = any(keyword in text_blob for keyword in BENIGN_TRANSACTIONAL_KEYWORDS)
    has_links = bool(report_input.urls or report_input.url_analysis)
    thread_signal = bool(report_input.in_reply_to) or normalized_subject.startswith("re:")
    high_conf_lookalike = any(str(item.get("confidence") or "").lower() == "high" for item in lookalike_matches)
    same_org_impersonation = bool(
        report_input.mailbox_domain
        and any(
            str(item.get("target_domain") or "").lower() == report_input.mailbox_domain.lower()
            for item in lookalike_matches
        )
    )

    if suspicious_attachments:
        threat_score += 38
        investigation_priority_score += 34
        automation_confidence_score -= 18
        analyst_worthy = True
        strong_threat_signals += 1
        add_reason(
            "SUSPICIOUS_ATTACHMENT",
            f"Suspicious attachment types were observed ({', '.join(sorted(set(suspicious_attachments))[:3])}).",
        )

    if credential_theme and has_links:
        threat_score += 28
        automation_confidence_score += 12
        strong_threat_signals += 1
        add_reason("CREDENTIAL_LINK", "Credential-themed language appears together with one or more message URLs.")

    if suspicious_redirects:
        threat_score += 24
        automation_confidence_score += 10
        strong_threat_signals += 1
        add_reason("SUSPICIOUS_REDIRECT", "URL analysis shows redirect, shortener, or domain-switch behavior.")
    elif has_links and report_input.risk_score >= 60:
        threat_score += 10
        add_reason("RISKY_LINK", "Message contains links and the existing suspiciousness score is elevated.")

    if finance_theme and (lookalike_matches or mismatch_signals or auth_failures):
        threat_score += 30
        investigation_priority_score += 40
        automation_confidence_score -= 24
        analyst_worthy = True
        strong_threat_signals += 1
        add_reason("BEC_IMPERSONATION", "Finance/payment language appears together with impersonation or sender-routing anomalies.")
    elif finance_theme:
        threat_score += 8
        investigation_priority_score += 8
        add_reason("FINANCE_LANGUAGE", "Finance/payment language is present and should be treated with caution.")

    if thread_signal and (has_links or suspicious_attachments):
        threat_score += 28
        investigation_priority_score += 36
        automation_confidence_score -= 22
        analyst_worthy = True
        strong_threat_signals += 1
        add_reason("THREAD_HIJACK_SIGNAL", "Message looks like a reply-chain continuation while introducing a new payload.")

    if lookalike_matches:
        highest_confidence = _highest_lookalike_confidence(lookalike_matches)
        threat_score += LOOKALIKE_CONFIDENCE_WEIGHT[highest_confidence]
        investigation_priority_score += LOOKALIKE_INVESTIGATION_WEIGHT[highest_confidence]
        automation_confidence_score -= 10 if highest_confidence == "low" else 18
        strong_threat_signals += 1 if highest_confidence != "low" else 0
        if same_org_impersonation or highest_confidence == "high":
            analyst_worthy = True
        add_reason(
            "LOOKALIKE_DOMAIN",
            f"Sender-domain lookalike analysis found suspected impersonation indicators (strongest confidence {highest_confidence}).",
        )

    if auth_failures:
        threat_score += min(8 * len(auth_failures), 22)
        add_reason("AUTH_FAILURES", f"Sender authentication did not align cleanly ({', '.join(auth_failures)}).")
        if len(auth_failures) >= 2 and mismatch_signals:
            threat_score += 12
            investigation_priority_score += 12
            automation_confidence_score -= 8
            strong_threat_signals += 1
            add_reason("AUTH_ROUTING_MISMATCH", "Authentication failures appear alongside Reply-To or Return-Path mismatches.")

    if report_input.risk_score >= 80:
        threat_score += 10
    elif report_input.risk_score >= 60:
        threat_score += 5

    if _has_any_header(headers, HEADER_LIST_INDICATORS):
        bulk_benign_score += 30
        strong_bulk_signals += 1
        add_reason("LIST_HEADERS", "Mailing-list headers are present, which is typical for bulk or newsletter traffic.")

    if _header_text(headers, "list-unsubscribe"):
        bulk_benign_score += 20
        strong_bulk_signals += 1
        add_reason("LIST_UNSUBSCRIBE", "List-Unsubscribe is present, which is common for graymail and promotional traffic.")

    list_unsubscribe_post = _header_text(headers, "list-unsubscribe-post")
    if "list-unsubscribe=one-click" in list_unsubscribe_post.lower():
        bulk_benign_score += 12
        strong_bulk_signals += 1
        add_reason("ONE_CLICK_UNSUBSCRIBE", "One-click unsubscribe metadata is present, which strongly suggests legitimate bulk delivery.")

    precedence = _header_text(headers, "precedence").strip().lower()
    if precedence in BULK_PRECEDENCE_VALUES:
        bulk_benign_score += 24
        strong_bulk_signals += 1
        add_reason("BULK_PRECEDENCE", f"Precedence header is set to {precedence}, which is typical for bulk traffic.")

    auto_submitted = _header_text(headers, "auto-submitted").strip().lower()
    if auto_submitted and auto_submitted != "no":
        bulk_benign_score += 26
        strong_bulk_signals += 1
        add_reason("AUTO_SUBMITTED", "Auto-Submitted indicates the message was generated automatically rather than sent manually.")

    if marketing_theme:
        bulk_benign_score += 18
        add_reason("MARKETING_CONTENT", "Content contains newsletter or promotional language commonly seen in bulk mail.")

    if benign_transactional_theme and not suspicious_attachments and not suspicious_redirects and not lookalike_matches:
        bulk_benign_score += 8
        add_reason("BENIGN_TRANSACTIONAL", "Content looks more like routine transactional or operational mail than phishing.")

    if auth_all_pass and not mismatch_signals and not lookalike_matches:
        bulk_benign_score += 10

    if strong_bulk_signals >= 2 and threat_score <= 30:
        automation_confidence_score += 25
    if strong_threat_signals >= 2 and not analyst_worthy:
        automation_confidence_score += 20
    if analyst_worthy:
        automation_confidence_score -= 22
    if bulk_benign_score >= 40 and threat_score >= 45:
        automation_confidence_score -= 16
        add_reason("CONFLICTING_SIGNALS", "Bulk-mail indicators are present, but they conflict with threat indicators.")
    if not reasons:
        automation_confidence_score -= 10

    if bulk_benign_score >= 50:
        investigation_priority_score -= 28
    if not analyst_worthy and threat_score >= 65 and automation_confidence_score >= 65:
        investigation_priority_score -= 22

    threat_score = _clamp_score(threat_score - _bulk_offset(threat_score, bulk_benign_score, analyst_worthy))
    bulk_benign_score = _clamp_score(bulk_benign_score)
    investigation_priority_score = _clamp_score(max(investigation_priority_score, threat_score // 2))
    automation_confidence_score = _clamp_score(automation_confidence_score)

    bucket = _select_bucket(
        threat_score=threat_score,
        bulk_benign_score=bulk_benign_score,
        investigation_priority_score=investigation_priority_score,
        automation_confidence_score=automation_confidence_score,
        analyst_worthy=analyst_worthy,
        suspicious_attachments=bool(suspicious_attachments),
        thread_signal=thread_signal and (has_links or bool(suspicious_attachments)),
        has_deception=bool(lookalike_matches or mismatch_signals or auth_failures),
    )

    summary = _build_summary(bucket=bucket, reasons=reasons, analyst_worthy=analyst_worthy)

    return ReportTriageAssessmentResult(
        threat_score=threat_score,
        bulk_benign_score=bulk_benign_score,
        investigation_priority_score=investigation_priority_score,
        automation_confidence_score=automation_confidence_score,
        bucket=bucket,
        analyst_worthy=analyst_worthy,
        summary=summary,
        reason_codes=reason_codes[:6],
        reasons=reasons[:4],
    )


def _build_text_blob(report_input: ReportTriageInput) -> str:
    return " ".join(
        part
        for part in [
            normalize_subject(report_input.subject),
            normalize_text(report_input.body_text),
            normalize_text(strip_html(report_input.body_html)),
            normalize_text(report_input.from_display_name),
        ]
        if part
    )


def _normalize_headers(headers: dict[str, Any] | None) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key, value in (headers or {}).items():
        lowered = str(key).strip().lower()
        if not lowered:
            continue
        if isinstance(value, list):
            items = [str(item) for item in value if str(item).strip()]
        else:
            cleaned = str(value).strip()
            items = [cleaned] if cleaned else []
        if items:
            normalized[lowered] = items
    return normalized


def _has_any_header(headers: dict[str, list[str]], names: set[str]) -> bool:
    return any(name in headers for name in names)


def _header_text(headers: dict[str, list[str]], name: str) -> str:
    return " ".join(headers.get(name.lower(), []))


def _highest_lookalike_confidence(matches: list[dict[str, Any]]) -> str:
    score = {"low": 1, "medium": 2, "high": 3}
    best = "low"
    for item in matches:
        value = str(item.get("confidence") or "low").lower()
        if score.get(value, 0) > score[best]:
            best = value
    return best


def _sender_mismatch_signals(report_input: ReportTriageInput) -> list[str]:
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


def _bulk_offset(threat_score: int, bulk_score: int, analyst_worthy: bool) -> int:
    if analyst_worthy:
        return 0
    if threat_score <= 25:
        return min(bulk_score // 3, 18)
    if threat_score <= 45 and bulk_score >= 40:
        return 10
    return 0


def _select_bucket(
    *,
    threat_score: int,
    bulk_benign_score: int,
    investigation_priority_score: int,
    automation_confidence_score: int,
    analyst_worthy: bool,
    suspicious_attachments: bool,
    thread_signal: bool,
    has_deception: bool,
) -> str:
    if analyst_worthy and threat_score >= 35:
        return "NEEDS_INVESTIGATION"
    if suspicious_attachments or thread_signal:
        return "NEEDS_INVESTIGATION"
    if bulk_benign_score >= 70 and threat_score <= 25:
        return "BULK_SPAM"
    if (
        threat_score <= 20
        and bulk_benign_score < 70
        and not has_deception
    ):
        return "LIKELY_BENIGN"
    if threat_score >= 65 and automation_confidence_score >= 65 and investigation_priority_score < 60:
        return "AUTOMATION_READY"
    if threat_score >= 55:
        return "NEEDS_INVESTIGATION"
    return "UNCERTAIN"


def _build_summary(*, bucket: str, reasons: list[str], analyst_worthy: bool) -> str:
    lead = reasons[0] if reasons else "Signals are limited and should be reviewed in context."
    if bucket == "NEEDS_INVESTIGATION":
        if analyst_worthy:
            return f"High-value phishing indicators suggest this report deserves analyst review. {lead}"
        return f"Threat indicators are elevated enough to keep this report in the analyst queue. {lead}"
    if bucket == "AUTOMATION_READY":
        return f"Commodity malicious indicators are strong enough for automation-first handling. {lead}"
    if bucket == "BULK_SPAM":
        return f"Bulk or graymail indicators dominate and no high-value threat signal currently stands out. {lead}"
    if bucket == "LIKELY_BENIGN":
        return f"Signals currently align more with benign or routine email than with phishing. {lead}"
    return f"Signals are mixed or incomplete, so this report should remain in a lower-confidence review lane. {lead}"


def _has_suspicious_attachment_extension(name: str) -> bool:
    lowered = name.strip().lower()
    return any(lowered.endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS)


def _email_domain(value: str | None) -> str | None:
    if not value:
        return None
    addr = parseaddr(value)[1] or value
    cleaned = addr.strip().strip("<>").lower()
    if "@" not in cleaned:
        return None
    return cleaned.rsplit("@", 1)[-1] or None


def _clamp_score(value: int) -> int:
    return max(0, min(int(value), 100))

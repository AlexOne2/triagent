from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attachment import Attachment
from app.models.campaign import ReportFeature
from app.models.report import Report
from app.services.analysis import body_snippet, normalize_subject

TOKEN_RE = re.compile(r"[a-z0-9]{2,}", re.IGNORECASE)
FEATURE_VERSION = 1


@dataclass
class FeaturePayload:
    subject_norm: str
    body_simhash: str
    from_domain: str | None
    reply_to_domains: list[str]
    return_path_domain: str | None
    originating_ip: str | None
    url_domains: list[str]
    attachment_hashes: list[str]
    semantic_vector: list[float] | None


def email_domain(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    if "@" not in cleaned:
        return None
    domain = cleaned.rsplit("@", 1)[-1]
    return domain or None


def url_domain(value: str) -> str | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}", scheme="http")
    hostname = parsed.hostname
    if not hostname:
        return None
    return hostname.lower()


def _simhash_tokens(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def simhash64(text: str) -> str:
    tokens = _simhash_tokens(text)
    if not tokens:
        return "0" * 16
    weights = [0] * 64
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        bits = int.from_bytes(digest[:8], "big")
        for idx in range(64):
            if bits & (1 << idx):
                weights[idx] += 1
            else:
                weights[idx] -= 1
    value = 0
    for idx, score in enumerate(weights):
        if score >= 0:
            value |= 1 << idx
    return f"{value:016x}"


def hamming_similarity(hex_a: str | None, hex_b: str | None) -> float:
    if not hex_a or not hex_b:
        return 0.0
    try:
        a = int(hex_a, 16)
        b = int(hex_b, 16)
    except ValueError:
        return 0.0
    distance = (a ^ b).bit_count()
    return max(0.0, 1.0 - (distance / 64.0))


def jaccard_similarity(a: Iterable[str], b: Iterable[str]) -> float:
    set_a = {item for item in a if item}
    set_b = {item for item in b if item}
    if not set_a and not set_b:
        return 0.0
    union_size = len(set_a | set_b)
    if union_size == 0:
        return 0.0
    return len(set_a & set_b) / union_size


def subject_similarity(a: str | None, b: str | None) -> float:
    if not a or not b:
        return 0.0
    tokens_a = set(_simhash_tokens(a))
    tokens_b = set(_simhash_tokens(b))
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def temporal_decay(days_old: float, half_life_days: float = 14.0) -> float:
    if days_old <= 0:
        return 1.0
    return math.exp(-days_old / max(half_life_days, 1e-6))


def build_feature_payload(report: Report, attachment_hashes: list[str] | None = None) -> FeaturePayload:
    subject_norm = normalize_subject(report.subject)
    snippet = body_snippet(report.body_text, report.body_html, length=1200)
    body_hash = simhash64(snippet)
    reply_domains = sorted(
        {
            domain
            for item in (report.reply_to or [])
            for domain in [email_domain(item)]
            if domain
        }
    )
    url_domains = sorted(
        {
            domain
            for item in (report.urls_json or [])
            for domain in [url_domain(item)]
            if domain
        }
    )
    hashes = sorted({item.lower() for item in (attachment_hashes or []) if item})
    return FeaturePayload(
        subject_norm=subject_norm,
        body_simhash=body_hash,
        from_domain=email_domain(report.from_addr),
        reply_to_domains=reply_domains,
        return_path_domain=email_domain(report.return_path),
        originating_ip=(report.originating_ip or None),
        url_domains=url_domains,
        attachment_hashes=hashes,
        semantic_vector=None,
    )


def upsert_report_feature(
    db: Session,
    report: Report,
    *,
    attachment_hashes: list[str] | None = None,
) -> ReportFeature:
    if attachment_hashes is None:
        attachment_hashes = [
            item.sha256
            for item in db.execute(
                select(Attachment).where(Attachment.report_id == report.id)
            )
            .scalars()
            .all()
            if item.sha256
        ]

    payload = build_feature_payload(report, attachment_hashes=attachment_hashes)
    feature = db.get(ReportFeature, report.id)
    if feature is None:
        feature = ReportFeature(report_id=report.id)
        db.add(feature)

    feature.subject_norm = payload.subject_norm or None
    feature.body_simhash = payload.body_simhash or None
    feature.from_domain = payload.from_domain
    feature.reply_to_domains_json = payload.reply_to_domains or None
    feature.return_path_domain = payload.return_path_domain
    feature.originating_ip = payload.originating_ip
    feature.url_domains_json = payload.url_domains or None
    feature.attachment_hashes_json = payload.attachment_hashes or None
    feature.semantic_vector_json = payload.semantic_vector
    feature.feature_version = FEATURE_VERSION
    db.flush()
    return feature

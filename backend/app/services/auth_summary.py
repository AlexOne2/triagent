from __future__ import annotations

from functools import lru_cache
import re
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver

from app.core.config import get_settings
from app.models.report import Report

AUTH_STATUS_VALUES = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "temperror",
    "permerror",
    "none",
    "unknown",
}


def _normalize_status(value: str | None) -> str:
    if not value:
        return "unknown"
    cleaned = value.strip().lower()
    return cleaned if cleaned in AUTH_STATUS_VALUES else "unknown"


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _header_value(headers: dict[str, Any], name: str) -> str | None:
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    if value is None:
        for key, item in headers.items():
            if key.lower() == name.lower():
                value = item
                break
    if value is None:
        return None
    if isinstance(value, list):
        return "\n".join(str(item) for item in value if item is not None)
    return str(value)


def _header_values(headers: dict[str, Any], name: str) -> list[str]:
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    if value is None:
        for key, item in headers.items():
            if key.lower() == name.lower():
                value = item
                break
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _extract_param(blob: str | None, key: str) -> str | None:
    if not blob:
        return None
    pattern = re.compile(rf"{re.escape(key)}=([^\s;]+)", re.IGNORECASE)
    match = pattern.search(blob)
    return _clean(match.group(1)) if match else None


def _extract_domain(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().strip("<>")
    if "@" not in cleaned:
        return None
    domain = cleaned.rsplit("@", 1)[-1].strip().lower()
    return domain or None


def _extract_method_chunks(blob: str | None, method: str) -> list[tuple[str, str]]:
    if not blob:
        return []
    pattern = re.compile(
        rf"(?:^|[\s;]){re.escape(method)}=([a-z_]+)(.*?)(?=(?:^|[\s;])(?:spf|dkim|dmarc|arc)=|$)",
        re.IGNORECASE | re.DOTALL,
    )
    return [(_normalize_status(match.group(1)), match.group(0).strip()) for match in pattern.finditer(blob)]


def _first_status(chunks: list[tuple[str, str]]) -> str:
    return chunks[0][0] if chunks else "unknown"


def _coalesce(*values: str | None) -> str | None:
    for value in values:
        if value:
            return value
    return None


def _extract_parenthesized(blob: str | None) -> str | None:
    if not blob:
        return None
    match = re.search(r"\(([^()]*)\)", blob)
    return _clean(match.group(1)) if match else None


def _sanitize_rdns(value: str | None) -> str | None:
    cleaned = _clean(value)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered == "unknown":
        return None
    if re.fullmatch(r"\d+", cleaned):
        return None
    return cleaned


def _extract_received_spf_ip(received_spf: str | None) -> str | None:
    if not received_spf:
        return None
    explicit = _coalesce(_extract_param(received_spf, "client-ip"), _extract_param(received_spf, "client_ip"))
    if explicit:
        return explicit
    designates = re.search(r"designates\s+((?:\d{1,3}\.){3}\d{1,3})\s+as permitted sender", received_spf, re.IGNORECASE)
    if designates:
        return designates.group(1)
    return None


def _extract_received_spf_detail(received_spf: str | None) -> str | None:
    if not received_spf:
        return None
    return _extract_parenthesized(received_spf)


def _resolver() -> dns.resolver.Resolver:
    settings = get_settings()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = settings.auth_dns_timeout_seconds
    resolver.timeout = settings.auth_dns_timeout_seconds
    return resolver


@lru_cache(maxsize=256)
def _lookup_txt_records(name: str) -> tuple[str, ...]:
    settings = get_settings()
    if not settings.auth_dns_enabled:
        return ()
    try:
        answers = _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return ()
    records: list[str] = []
    for answer in answers:
        if hasattr(answer, "strings"):
            record = "".join(
                item.decode("utf-8", errors="replace") if isinstance(item, bytes) else str(item)
                for item in answer.strings
            )
        else:
            record = answer.to_text().replace('" "', "").strip('"')
        cleaned = _clean(record)
        if cleaned:
            records.append(cleaned)
    return tuple(records)


@lru_cache(maxsize=256)
def _lookup_ptr_record(ip_address: str) -> str | None:
    settings = get_settings()
    if not settings.auth_dns_enabled:
        return None
    try:
        answer = _resolver().resolve_address(ip_address)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.SyntaxError):
        return None
    for item in answer:
        cleaned = _clean(item.to_text().rstrip("."))
        if cleaned:
            return cleaned
    return None


def _resolve_spf_dns_record(domain: str | None) -> str | None:
    if not domain:
        return None
    for record in _lookup_txt_records(domain):
        if record.lower().startswith("v=spf1"):
            return record
    return None


def _resolve_dmarc_dns_record(domain: str | None) -> str | None:
    if not domain:
        return None
    for record in _lookup_txt_records(f"_dmarc.{domain}"):
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


@dataclass
class ParsedDkimSignature:
    result: str
    signing_domain: str | None
    identity: str | None
    selector: str | None
    algorithm: str | None
    canonicalization: str | None
    raw: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "signing_domain": self.signing_domain,
            "identity": self.identity,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "canonicalization": self.canonicalization,
            "raw": self.raw,
        }


def _parse_dkim_signature_header(raw_header: str) -> dict[str, Any]:
    signing_domain = _extract_param(raw_header, "d")
    identity = _extract_param(raw_header, "i")
    selector = _extract_param(raw_header, "s")
    return {
        "signing_domain": signing_domain or _extract_domain(identity),
        "identity": identity,
        "selector": selector,
        "algorithm": _extract_param(raw_header, "a"),
        "canonicalization": _extract_param(raw_header, "c"),
        "raw": raw_header,
    }


def _merge_dkim_signature(parsed: ParsedDkimSignature, raw_fields: dict[str, Any] | None) -> ParsedDkimSignature:
    if not raw_fields:
        if not parsed.signing_domain and parsed.identity:
            parsed.signing_domain = _extract_domain(parsed.identity)
        return parsed
    parsed.signing_domain = parsed.signing_domain or raw_fields.get("signing_domain") or _extract_domain(parsed.identity)
    parsed.identity = parsed.identity or raw_fields.get("identity")
    parsed.selector = parsed.selector or raw_fields.get("selector")
    parsed.algorithm = parsed.algorithm or raw_fields.get("algorithm")
    parsed.canonicalization = parsed.canonicalization or raw_fields.get("canonicalization")
    if not parsed.raw:
        parsed.raw = raw_fields.get("raw") or ""
    return parsed


def _parse_dkim(auth_header: str | None, dkim_signature_headers: list[str]) -> dict[str, Any]:
    signatures: list[ParsedDkimSignature] = []
    raw_signatures = [_parse_dkim_signature_header(item) for item in dkim_signature_headers]
    for result, chunk in _extract_method_chunks(auth_header, "dkim"):
        parsed = ParsedDkimSignature(
            result=result,
            signing_domain=_extract_param(chunk, "header.d"),
            identity=_extract_param(chunk, "header.i"),
            selector=_extract_param(chunk, "header.s"),
            algorithm=_extract_param(chunk, "header.a"),
            canonicalization=_extract_param(chunk, "header.c"),
            raw=chunk,
        )
        signatures.append(_merge_dkim_signature(parsed, raw_signatures[len(signatures)] if len(raw_signatures) > len(signatures) else None))

    if not signatures and raw_signatures:
        for raw_fields in raw_signatures:
            signatures.append(
                ParsedDkimSignature(
                    result="unknown",
                    signing_domain=raw_fields.get("signing_domain"),
                    identity=raw_fields.get("identity"),
                    selector=raw_fields.get("selector"),
                    algorithm=raw_fields.get("algorithm"),
                    canonicalization=raw_fields.get("canonicalization"),
                    raw=raw_fields.get("raw") or "",
                )
            )

    return {
        "result": signatures[0].result if signatures else "unknown",
        "signature_count": len(signatures),
        "signatures": [item.as_dict() for item in signatures],
    }


def _parse_spf(
    auth_header: str | None,
    received_spf: str | None,
    *,
    return_path: str | None,
    originating_ip: str | None,
    originating_rdns: str | None,
) -> dict[str, Any]:
    auth_chunks = _extract_method_chunks(auth_header, "spf")
    result = _first_status(auth_chunks)
    primary = auth_chunks[0][1] if auth_chunks else (received_spf or "")
    authserv_id = _clean((auth_header or "").split(";", 1)[0]) if auth_header else None
    receiver = _extract_param(primary, "receiver")
    smtp_mailfrom = _extract_param(primary, "smtp.mailfrom")
    smtp_helo = _extract_param(primary, "smtp.helo")
    explicit_primary_ip = _coalesce(_extract_param(primary, "client-ip"), _extract_param(primary, "client_ip"))
    client_ip = _coalesce(
        explicit_primary_ip,
        _extract_received_spf_ip(received_spf),
        originating_ip,
    )

    if result == "unknown" and received_spf:
        received_lower = received_spf.lower()
        status_match = re.match(r"\s*([a-z_]+)", received_lower)
        result = _normalize_status(status_match.group(1) if status_match else None)

    return {
        "result": result,
        "source_header": "Received-SPF"
        if received_spf and not explicit_primary_ip
        else ("Authentication-Results" if auth_chunks else ("Received-SPF" if received_spf else None)),
        "authserv_id": authserv_id,
        "receiver": receiver,
        "smtp_mailfrom": smtp_mailfrom or return_path,
        "smtp_helo": smtp_helo,
        "return_path_domain": _extract_domain(return_path),
        "originating_ip": client_ip,
        "originating_rdns": _sanitize_rdns(originating_rdns),
        "raw": _clean(primary) or None,
        "detail": _extract_received_spf_detail(received_spf),
    }


def _parse_dmarc(auth_header: str | None, *, from_addr: str | None, return_path: str | None) -> dict[str, Any]:
    chunks = _extract_method_chunks(auth_header, "dmarc")
    raw = chunks[0][1] if chunks else None
    return {
        "result": _first_status(chunks),
        "header_from": _coalesce(_extract_param(raw, "header.from"), _extract_domain(from_addr)),
        "aligned_from_domain": _coalesce(_extract_param(raw, "header.from"), _extract_domain(from_addr)),
        "aligned_mailfrom_domain": _coalesce(_extract_param(raw, "smtp.mailfrom"), _extract_domain(return_path)),
        "policy": _coalesce(_extract_param(raw, "policy"), _extract_param(raw, "p")),
        "raw": raw,
    }


def _parse_arc(
    auth_header: str | None,
    arc_auth_header: str | None,
    arc_seal_header: str | None,
    arc_message_signature_header: str | None,
) -> dict[str, Any]:
    auth_chunks = _extract_method_chunks(auth_header, "arc")
    overall = _first_status(auth_chunks)
    if overall == "unknown":
        overall = _normalize_status(_extract_param(arc_seal_header, "cv"))

    return {
        "result": overall,
        "instance": _coalesce(
            _extract_param(arc_seal_header, "i"),
            _extract_param(arc_message_signature_header, "i"),
            _extract_param(arc_auth_header, "i"),
        ),
        "seal_result": _normalize_status(_extract_param(arc_seal_header, "cv")),
        "message_signature_result": _normalize_status(_extract_param(arc_message_signature_header, "cv")),
        "auth_results": arc_auth_header,
        "seal": arc_seal_header,
        "message_signature": arc_message_signature_header,
        "raw": _coalesce(
            auth_chunks[0][1] if auth_chunks else None,
            arc_auth_header,
            arc_seal_header,
            arc_message_signature_header,
        ),
    }


def build_auth_summary(report: Report) -> dict[str, Any]:
    headers = dict(report.headers_json or {})
    auth_header = _header_value(headers, "Authentication-Results")
    received_spf = _header_value(headers, "Received-SPF")
    dkim_signature_headers = _header_values(headers, "DKIM-Signature")
    arc_auth_header = _header_value(headers, "ARC-Authentication-Results")
    arc_seal_header = _header_value(headers, "ARC-Seal")
    arc_message_signature_header = _header_value(headers, "ARC-Message-Signature")

    spf = _parse_spf(
        auth_header,
        received_spf,
        return_path=report.return_path,
        originating_ip=report.originating_ip,
        originating_rdns=report.originating_rdns,
    )
    dkim = _parse_dkim(auth_header, dkim_signature_headers)
    dmarc = _parse_dmarc(auth_header, from_addr=report.from_addr, return_path=report.return_path)
    arc = _parse_arc(auth_header, arc_auth_header, arc_seal_header, arc_message_signature_header)
    spf_dns_record = _resolve_spf_dns_record(spf.get("return_path_domain") or _extract_domain(spf.get("smtp_mailfrom")))
    dmarc_dns_record = _resolve_dmarc_dns_record(dmarc.get("header_from"))
    resolved_rdns = _coalesce(spf.get("originating_rdns"), _lookup_ptr_record(spf.get("originating_ip") or ""))
    if spf_dns_record:
        spf["dns_record"] = spf_dns_record
    if dmarc_dns_record:
        dmarc["dns_record"] = dmarc_dns_record
    spf["originating_rdns"] = resolved_rdns

    raw_headers = {
        "authentication_results": auth_header,
        "received_spf": received_spf,
        "arc_authentication_results": arc_auth_header,
        "arc_seal": arc_seal_header,
        "arc_message_signature": arc_message_signature_header,
    }

    return {
        "overview": {
            "spf": spf["result"],
            "dkim": dkim["result"],
            "dmarc": dmarc["result"],
            "arc": arc["result"],
        },
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "arc": arc,
        "raw_headers": raw_headers,
    }

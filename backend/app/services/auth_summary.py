from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

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


def _parse_dkim(auth_header: str | None) -> dict[str, Any]:
    signatures: list[ParsedDkimSignature] = []
    for result, chunk in _extract_method_chunks(auth_header, "dkim"):
        signatures.append(
            ParsedDkimSignature(
                result=result,
                signing_domain=_extract_param(chunk, "header.d"),
                identity=_extract_param(chunk, "header.i"),
                selector=_extract_param(chunk, "header.s"),
                algorithm=_extract_param(chunk, "header.a"),
                canonicalization=_extract_param(chunk, "header.c"),
                raw=chunk,
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
    client_ip = _coalesce(_extract_param(primary, "client-ip"), _extract_param(primary, "client_ip"), originating_ip)

    if result == "unknown" and received_spf:
        received_lower = received_spf.lower()
        status_match = re.match(r"\s*([a-z_]+)", received_lower)
        result = _normalize_status(status_match.group(1) if status_match else None)

    return {
        "result": result,
        "source_header": "Authentication-Results" if auth_chunks else ("Received-SPF" if received_spf else None),
        "authserv_id": authserv_id,
        "receiver": receiver,
        "smtp_mailfrom": smtp_mailfrom or return_path,
        "smtp_helo": smtp_helo,
        "return_path_domain": _extract_domain(return_path),
        "originating_ip": client_ip,
        "originating_rdns": originating_rdns,
        "raw": _clean(primary) or None,
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
    dkim = _parse_dkim(auth_header)
    dmarc = _parse_dmarc(auth_header, from_addr=report.from_addr, return_path=report.return_path)
    arc = _parse_arc(auth_header, arc_auth_header, arc_seal_header, arc_message_signature_header)

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

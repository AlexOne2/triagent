from __future__ import annotations

from email import policy
from email.parser import BytesParser
import re
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, List, Optional


def _decode_header(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _extract_addresses(header_value: Optional[str]) -> List[str]:
    if not header_value:
        return []
    return [addr for _, addr in getaddresses([header_value]) if addr]


def _get_body_parts(msg) -> tuple[str | None, str | None]:
    text_parts: List[str] = []
    html_parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            try:
                payload = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            if content_type == "text/plain" and payload:
                text_parts.append(str(payload))
            elif content_type == "text/html" and payload:
                html_parts.append(str(payload))
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
        if msg.get_content_type() == "text/html":
            html_parts.append(str(payload))
        else:
            text_parts.append(str(payload))

    body_text = "\n".join([p for p in text_parts if p]) or None
    body_html = "\n".join([p for p in html_parts if p]) or None
    return body_text, body_html


def parse_eml(raw_bytes: bytes) -> Dict[str, Any]:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    subject = _decode_header(msg.get("subject"))
    from_header = _decode_header(msg.get("from"))
    sender_header = _decode_header(msg.get("sender"))
    to_header = _decode_header(msg.get("to"))
    cc_header = _decode_header(msg.get("cc"))
    reply_to_header = _decode_header(msg.get("reply-to"))
    in_reply_to_header = _decode_header(msg.get("in-reply-to"))
    return_path_header = _decode_header(msg.get("return-path"))

    from_addrs = getaddresses([from_header] if from_header else [])
    from_addr = from_addrs[0][1] if from_addrs else None
    from_display_name = from_addrs[0][0] if from_addrs else None

    to_addrs = _extract_addresses(to_header)
    cc_addrs = _extract_addresses(cc_header)
    reply_to_addrs = _extract_addresses(reply_to_header)

    date_header = msg.get("date")
    date = None
    if date_header:
        try:
            date = parsedate_to_datetime(str(date_header))
        except Exception:
            date = None
    message_id = msg.get("message-id")

    body_text, body_html = _get_body_parts(msg)

    headers: Dict[str, Any] = {k: v for (k, v) in msg.items()}
    received_headers = msg.get_all("received", [])
    originating_ip = _extract_originating_ip(received_headers)
    originating_rdns = _extract_originating_rdns(received_headers)

    return {
        "message_id": message_id,
        "subject": subject,
        "from_addr": from_addr,
        "from_display_name": from_display_name,
        "sender": sender_header,
        "to_addrs": to_addrs,
        "cc_addrs": cc_addrs,
        "reply_to": reply_to_addrs,
        "in_reply_to": in_reply_to_header,
        "return_path": return_path_header,
        "date": date,
        "body_text": body_text,
        "body_html": body_html,
        "headers_json": headers,
        "raw_source": raw_bytes.decode("utf-8", errors="replace"),
        "originating_ip": originating_ip,
        "originating_rdns": originating_rdns,
    }


def _extract_originating_ip(received_headers: list[str]) -> str | None:
    if not received_headers:
        return None
    header = received_headers[-1]
    match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", header)
    if match:
        return match.group(0)
    return None


def _extract_originating_rdns(received_headers: list[str]) -> str | None:
    if not received_headers:
        return None
    header = received_headers[-1]
    match = re.search(r"from\s+([^\s\(]+)", header, re.IGNORECASE)
    if match:
        candidate = match.group(1).strip()
        lowered = candidate.lower()
        if lowered == "unknown" or re.fullmatch(r"\d+", candidate):
            return None
        return candidate
    return None

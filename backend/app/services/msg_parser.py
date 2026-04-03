from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.parser import HeaderParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
import tempfile
from typing import Any

import extract_msg

from app.services.eml_parser import _extract_originating_ip, _extract_originating_rdns, _serialize_headers


class MsgParseError(RuntimeError):
    pass


@dataclass
class ParsedMsgAttachment:
    filename: str
    content_type: str | None
    data: bytes


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _extract_addresses(value: str | None) -> list[str]:
    if not value:
        return []
    return [addr for _, addr in getaddresses([value]) if addr]


def _extract_attachment_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if callable(value):
        try:
            value = value()
        except Exception:
            return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def _parse_headers(raw_headers: str | None) -> tuple[dict[str, Any], list[str]]:
    if not raw_headers:
        return {}, []
    parsed = HeaderParser(policy=policy.default).parsestr(raw_headers)
    headers = _serialize_headers(parsed)
    received_headers = [str(item) for item in parsed.get_all("received", [])]
    return headers, received_headers


def _normalize_msg(message: Any, raw_bytes: bytes) -> tuple[dict[str, Any], list[ParsedMsgAttachment]]:
    raw_headers = _as_text(getattr(message, "header", None))
    headers_json, received_headers = _parse_headers(raw_headers)

    sender_value = _as_text(getattr(message, "sender", None))
    from_pairs = getaddresses([sender_value] if sender_value else [])
    from_addr = from_pairs[0][1] if from_pairs else None
    from_display_name = from_pairs[0][0] if from_pairs else None

    to_header = _as_text(getattr(message, "to", None)) or _as_text(headers_json.get("To"))
    cc_header = _as_text(getattr(message, "cc", None)) or _as_text(headers_json.get("Cc"))
    reply_to_header = _as_text(headers_json.get("Reply-To"))

    date_value = _as_text(getattr(message, "date", None)) or _as_text(headers_json.get("Date"))
    date = None
    if date_value:
        try:
            date = parsedate_to_datetime(date_value)
        except Exception:
            date = None

    message_id = (
        _as_text(getattr(message, "messageId", None))
        or _as_text(headers_json.get("Message-ID"))
        or _as_text(headers_json.get("Message-Id"))
    )
    in_reply_to = _as_text(headers_json.get("In-Reply-To"))
    return_path = _as_text(headers_json.get("Return-Path"))
    sender_header = _as_text(headers_json.get("Sender")) or sender_value

    body_text = _as_text(getattr(message, "body", None))
    body_html = _as_text(getattr(message, "htmlBody", None))
    if body_html and not body_text:
        body_text = _as_text(getattr(message, "body", None))

    attachments: list[ParsedMsgAttachment] = []
    for index, item in enumerate(getattr(message, "attachments", []) or []):
        payload = _extract_attachment_bytes(getattr(item, "data", None))
        if payload is None:
            continue
        filename = (
            _as_text(getattr(item, "longFilename", None))
            or _as_text(getattr(item, "shortFilename", None))
            or f"attachment-{index + 1}.bin"
        )
        content_type = (
            _as_text(getattr(item, "mimetype", None))
            or _as_text(getattr(item, "mimeType", None))
            or _as_text(getattr(item, "contentType", None))
        )
        attachments.append(
            ParsedMsgAttachment(
                filename=filename,
                content_type=content_type,
                data=payload,
            )
        )

    payload = {
        "message_id": message_id,
        "subject": _as_text(getattr(message, "subject", None)),
        "from_addr": from_addr,
        "from_display_name": from_display_name,
        "sender": sender_header,
        "to_addrs": _extract_addresses(to_header),
        "cc_addrs": _extract_addresses(cc_header),
        "reply_to": _extract_addresses(reply_to_header),
        "in_reply_to": in_reply_to,
        "return_path": return_path,
        "date": date,
        "body_text": body_text,
        "body_html": body_html,
        "headers_json": headers_json or None,
        "raw_source": raw_bytes.decode("utf-8", errors="replace"),
        "originating_ip": _extract_originating_ip(received_headers),
        "originating_rdns": _extract_originating_rdns(received_headers),
    }
    return payload, attachments


def parse_msg(raw_bytes: bytes) -> tuple[dict[str, Any], list[ParsedMsgAttachment]]:
    if not raw_bytes:
        raise MsgParseError("Invalid or unsupported .msg file")

    temp_path = Path("")
    message = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as handle:
            handle.write(raw_bytes)
            temp_path = Path(handle.name)

        message = extract_msg.Message(str(temp_path))
        payload, attachments = _normalize_msg(message, raw_bytes)
        return payload, attachments
    except MsgParseError:
        raise
    except Exception as exc:
        raise MsgParseError("Invalid or unsupported .msg file") from exc
    finally:
        if message is not None:
            try:
                message.close()
            except Exception:
                pass
        if temp_path and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass

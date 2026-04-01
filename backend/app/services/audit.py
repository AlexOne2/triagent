from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Select, and_, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.security_audit import AuditActorType, AuditChainState, AuditExport, SecurityAuditEvent

GENESIS_HASH = "0" * 64
AUDIT_SCHEMA_VERSION = 1
SENSITIVE_METADATA_KEYS = (
    "password",
    "secret",
    "token",
    "authorization",
    "api_key",
    "raw_source",
    "body_html",
    "body_text",
    "headers",
)


@dataclass
class AuditRequestMeta:
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _infer_actor_type(actor_user_id: int | None, actor_api_key_id: int | None) -> AuditActorType:
    if actor_user_id is not None:
        return AuditActorType.USER
    if actor_api_key_id is not None:
        return AuditActorType.API_KEY
    return AuditActorType.SYSTEM


def _sanitize_metadata_value(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if any(token in normalized_key for token in SENSITIVE_METADATA_KEYS):
                continue
            result[str(key)] = _sanitize_metadata_value(item)
        return result
    if isinstance(value, list):
        return [_sanitize_metadata_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def sanitize_metadata(metadata: dict[str, Any] | None, max_bytes: int) -> dict[str, Any] | None:
    if metadata is None:
        return None
    sanitized = _sanitize_metadata_value(metadata)
    payload = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    if len(payload) <= max_bytes:
        return sanitized
    digest = hashlib.sha256(payload).hexdigest()
    preview = payload[:max(128, max_bytes // 2)].decode("utf-8", errors="ignore")
    return {
        "truncated": True,
        "original_sha256": digest,
        "preview": preview,
        "max_bytes": max_bytes,
    }


def canonical_event_payload(event: SecurityAuditEvent) -> str:
    payload = {
        "event_uuid": event.event_uuid,
        "actor_type": event.actor_type.value,
        "actor_user_id": event.actor_user_id,
        "actor_api_key_id": event.actor_api_key_id,
        "action": event.action,
        "target_type": event.target_type,
        "target_id": event.target_id,
        "outcome": event.outcome,
        "request_id": event.request_id,
        "correlation_id": event.correlation_id,
        "schema_version": event.schema_version,
        "metadata_json": event.metadata_json,
        "ip": event.ip,
        "user_agent": event.user_agent,
        "created_at": _iso_utc(event.created_at),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_event_hash(event: SecurityAuditEvent, prev_hash: str) -> str:
    serialized = canonical_event_payload(event)
    return hashlib.sha256(f"{serialized}|{prev_hash}".encode("utf-8")).hexdigest()


class AuditService:
    def __init__(self, db: Session, settings: Settings | None = None) -> None:
        self.db = db
        self.settings = settings or get_settings()

    def emit(
        self,
        *,
        action: str,
        outcome: str,
        target_type: str | None = None,
        target_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        actor_user_id: int | None = None,
        actor_api_key_id: int | None = None,
        actor_type: AuditActorType | None = None,
        request_meta: AuditRequestMeta | None = None,
        created_at: datetime | None = None,
    ) -> SecurityAuditEvent:
        normalized_actor_type = actor_type or _infer_actor_type(actor_user_id, actor_api_key_id)
        metadata_json = sanitize_metadata(metadata, self.settings.audit_max_metadata_bytes)
        created = created_at or utcnow()
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        else:
            created = created.astimezone(timezone.utc)

        chain_state = self.db.execute(
            select(AuditChainState).where(AuditChainState.id == 1).with_for_update()
        ).scalar_one_or_none()
        if chain_state is None:
            chain_state = AuditChainState(id=1, last_event_id=None, last_hash=GENESIS_HASH)
            self.db.add(chain_state)
            self.db.flush()

        previous_hash = chain_state.last_hash or GENESIS_HASH

        event = SecurityAuditEvent(
            event_uuid=str(uuid.uuid4()),
            actor_user_id=actor_user_id,
            actor_api_key_id=actor_api_key_id,
            actor_type=normalized_actor_type,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            request_id=request_meta.request_id if request_meta else None,
            correlation_id=request_meta.correlation_id if request_meta else None,
            schema_version=AUDIT_SCHEMA_VERSION,
            metadata_json=metadata_json,
            ip=request_meta.ip if request_meta else None,
            user_agent=request_meta.user_agent if request_meta else None,
            prev_hash=previous_hash,
            event_hash="",
            created_at=created,
        )
        event.event_hash = compute_event_hash(event, previous_hash)
        self.db.add(event)
        self.db.flush()

        chain_state.last_event_id = event.id
        chain_state.last_hash = event.event_hash
        chain_state.updated_at = created

        return event

    def _query_events(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        action: str | None = None,
        outcome: str | None = None,
        actor_type: AuditActorType | None = None,
        actor_user_id: int | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
    ) -> Select[tuple[SecurityAuditEvent]]:
        query = select(SecurityAuditEvent)
        predicates = []
        if start is not None:
            predicates.append(SecurityAuditEvent.created_at >= start)
        if end is not None:
            predicates.append(SecurityAuditEvent.created_at <= end)
        if action:
            predicates.append(SecurityAuditEvent.action == action)
        if outcome:
            predicates.append(SecurityAuditEvent.outcome == outcome)
        if actor_type:
            predicates.append(SecurityAuditEvent.actor_type == actor_type)
        if actor_user_id is not None:
            predicates.append(SecurityAuditEvent.actor_user_id == actor_user_id)
        if target_type:
            predicates.append(SecurityAuditEvent.target_type == target_type)
        if target_id:
            predicates.append(SecurityAuditEvent.target_id == target_id)
        if request_id:
            predicates.append(SecurityAuditEvent.request_id == request_id)
        if predicates:
            query = query.where(and_(*predicates))
        return query

    def list_events(
        self,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        action: str | None = None,
        outcome: str | None = None,
        actor_type: AuditActorType | None = None,
        actor_user_id: int | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        request_id: str | None = None,
        limit: int = 100,
        cursor: int | None = None,
    ) -> tuple[list[SecurityAuditEvent], int | None]:
        query = self._query_events(
            start=start,
            end=end,
            action=action,
            outcome=outcome,
            actor_type=actor_type,
            actor_user_id=actor_user_id,
            target_type=target_type,
            target_id=target_id,
            request_id=request_id,
        )
        if cursor is not None:
            query = query.where(SecurityAuditEvent.id < cursor)

        rows = (
            self.db.execute(
                query.order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.desc()).limit(limit + 1)
            )
            .scalars()
            .all()
        )
        has_more = len(rows) > limit
        events = rows[:limit]
        next_cursor = events[-1].id if has_more and events else None
        return events, next_cursor

    def verify_chain(self, *, start: datetime | None = None, end: datetime | None = None) -> dict[str, Any]:
        ordered = (
            self.db.execute(
                self._query_events(start=start, end=end).order_by(SecurityAuditEvent.created_at.asc(), SecurityAuditEvent.id.asc())
            )
            .scalars()
            .all()
        )

        if not ordered:
            return {
                "valid": True,
                "checked_count": 0,
                "first_invalid_event_id": None,
                "expected_hash": None,
                "actual_hash": None,
                "range_start": _iso_utc(start),
                "range_end": _iso_utc(end),
            }

        previous_in_db = None
        first_created = ordered[0].created_at
        first_id = ordered[0].id
        if first_created is not None:
            previous_in_db = (
                self.db.execute(
                    select(SecurityAuditEvent)
                    .where(
                        or_(
                            SecurityAuditEvent.created_at < first_created,
                            and_(
                                SecurityAuditEvent.created_at == first_created,
                                SecurityAuditEvent.id < first_id,
                            ),
                        )
                    )
                    .order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )

        expected_prev = previous_in_db.event_hash if previous_in_db else ordered[0].prev_hash
        checked = 0
        for event in ordered:
            expected_hash = compute_event_hash(event, expected_prev)
            if event.prev_hash != expected_prev or event.event_hash != expected_hash:
                return {
                    "valid": False,
                    "checked_count": checked,
                    "first_invalid_event_id": event.id,
                    "expected_hash": expected_hash,
                    "actual_hash": event.event_hash,
                    "range_start": _iso_utc(ordered[0].created_at),
                    "range_end": _iso_utc(ordered[-1].created_at),
                }
            checked += 1
            expected_prev = event.event_hash

        return {
            "valid": True,
            "checked_count": checked,
            "first_invalid_event_id": None,
            "expected_hash": None,
            "actual_hash": None,
            "range_start": _iso_utc(ordered[0].created_at),
            "range_end": _iso_utc(ordered[-1].created_at),
        }

    def serialize_event(self, event: SecurityAuditEvent) -> dict[str, Any]:
        return {
            "id": event.id,
            "event_uuid": event.event_uuid,
            "actor_type": event.actor_type.value,
            "actor_user_id": event.actor_user_id,
            "actor_api_key_id": event.actor_api_key_id,
            "action": event.action,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "outcome": event.outcome,
            "request_id": event.request_id,
            "correlation_id": event.correlation_id,
            "schema_version": event.schema_version,
            "metadata_json": event.metadata_json,
            "ip": event.ip,
            "user_agent": event.user_agent,
            "prev_hash": event.prev_hash,
            "event_hash": event.event_hash,
            "created_at": event.created_at,
        }

    def ndjson_for_range(self, *, start: datetime, end: datetime) -> tuple[list[str], dict[str, Any]]:
        events = (
            self.db.execute(
                self._query_events(start=start, end=end).order_by(SecurityAuditEvent.created_at.asc(), SecurityAuditEvent.id.asc())
            )
            .scalars()
            .all()
        )
        lines = [json.dumps(self.serialize_event(event), default=str, separators=(",", ":")) for event in events]
        root_hash = events[-1].event_hash if events else GENESIS_HASH
        manifest = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "range_start": _iso_utc(start),
            "range_end": _iso_utc(end),
            "event_count": len(events),
            "root_hash": root_hash,
            "generated_at": _iso_utc(utcnow()),
        }
        return lines, manifest

    def record_export(
        self,
        *,
        range_start: datetime,
        range_end: datetime,
        event_count: int,
        root_hash: str,
        manifest_json: dict[str, Any],
        storage_uri: str,
        created_by: str,
    ) -> AuditExport:
        export = AuditExport(
            range_start=range_start,
            range_end=range_end,
            event_count=event_count,
            root_hash=root_hash,
            manifest_json=manifest_json,
            storage_uri=storage_uri,
            created_by=created_by,
        )
        self.db.add(export)
        self.db.flush()
        return export

    def list_exports(self, *, limit: int = 100) -> list[AuditExport]:
        return (
            self.db.execute(select(AuditExport).order_by(AuditExport.created_at.desc(), AuditExport.id.desc()).limit(limit))
            .scalars()
            .all()
        )

    def write_export_to_filesystem(
        self,
        *,
        base_path: str,
        file_stem: str,
        lines: list[str],
        manifest: dict[str, Any],
    ) -> str:
        target = Path(base_path)
        target.mkdir(parents=True, exist_ok=True)
        ndjson_path = target / f"{file_stem}.ndjson"
        manifest_path = target / f"{file_stem}.manifest.json"
        ndjson_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return str(ndjson_path)

from __future__ import annotations

import argparse
from base64 import b64decode
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, formataddr
import hashlib
from io import BytesIO
import json
from pathlib import Path
import shutil
import sys
from typing import Any
import zipfile

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.analysis import extract_urls

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "test_data" / "synthetic-corpus"
DEFAULT_SPEC_PATH = DEFAULT_OUTPUT_ROOT / "specs" / "canonical-scenarios.json"
GENERATOR_VERSION = "1"
MINIMAL_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WlH0r8AAAAASUVORK5CYII="
)


def load_spec(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_datetime(value: str | None) -> datetime:
    if value:
        return datetime.fromisoformat(value)
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _add_header(message: EmailMessage, name: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, list):
        for item in value:
            message[name] = str(item)
        return
    message[name] = str(value)


def _zip_bytes(member_name: str, payload: str) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, payload)
    return buffer.getvalue()


def _docm_placeholder_bytes(payload: str) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
                "<Override PartName=\"/word/document.xml\" "
                "ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>"
                "</Types>"
            ),
        )
        archive.writestr("word/document.xml", f"<document><body>{payload}</body></document>")
    return buffer.getvalue()


def _pdf_placeholder_bytes(payload: str) -> bytes:
    lines = [
        "%PDF-1.4",
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R >> endobj",
        f"4 0 obj << /Length {len(payload) + 18} >> stream",
        f"BT /F1 12 Tf 36 96 Td ({payload}) Tj ET",
        "endstream endobj",
        "xref 0 5",
        "0000000000 65535 f ",
        "trailer << /Root 1 0 R /Size 5 >>",
        "startxref",
        "0",
        "%%EOF",
    ]
    return "\n".join(lines).encode("utf-8")


def _calendar_bytes(payload: str) -> bytes:
    return payload.encode("utf-8")


def _png_bytes() -> bytes:
    return b64decode(MINIMAL_PNG_BASE64)


def _attachment_bytes(spec: dict[str, Any]) -> bytes:
    template = spec.get("template", "text_payload")
    payload = spec.get("text_payload", f"Synthetic placeholder for {spec.get('filename', 'attachment.bin')}")

    if template == "text_payload":
        return payload.encode("utf-8")
    if template == "zip_text_payload":
        return _zip_bytes(spec.get("archive_member", "payload.txt"), payload)
    if template == "docm_placeholder":
        return _docm_placeholder_bytes(payload)
    if template == "pdf_placeholder":
        return _pdf_placeholder_bytes(payload)
    if template == "ics_payload":
        return _calendar_bytes(payload)
    if template == "png_placeholder":
        return _png_bytes()

    raise ValueError(f"Unsupported attachment template: {template}")


def materialize_sample(sample: dict[str, Any]) -> bytes:
    message_spec = sample["message"]
    message = EmailMessage()

    from_addr = message_spec["from_addr"]
    from_display_name = message_spec.get("from_display_name")
    message["Subject"] = message_spec["subject"]
    message["From"] = formataddr((from_display_name, from_addr)) if from_display_name else from_addr
    _add_header(message, "To", ", ".join(message_spec.get("to_addrs", [])))
    if message_spec.get("cc_addrs"):
        _add_header(message, "Cc", ", ".join(message_spec["cc_addrs"]))
    if message_spec.get("reply_to"):
        _add_header(message, "Reply-To", ", ".join(message_spec["reply_to"]))
    _add_header(message, "Return-Path", message_spec.get("return_path"))
    _add_header(message, "Message-ID", message_spec.get("message_id"))
    _add_header(message, "In-Reply-To", message_spec.get("in_reply_to"))
    message["Date"] = format_datetime(_parse_datetime(message_spec.get("date")))

    for header_name, header_value in (message_spec.get("headers") or {}).items():
        _add_header(message, header_name, header_value)

    body_text = message_spec.get("body_text") or ""
    body_html = message_spec.get("body_html")
    if body_html:
        message.set_content(body_text)
        message.add_alternative(body_html, subtype="html")
    else:
        message.set_content(body_text)

    for attachment in message_spec.get("attachments", []):
        content_type = attachment.get("content_type", "application/octet-stream")
        maintype, subtype = content_type.split("/", 1)
        message.add_attachment(
            _attachment_bytes(attachment),
            maintype=maintype,
            subtype=subtype,
            filename=attachment["filename"],
        )

    return message.as_bytes()


def _manifest_entry(sample: dict[str, Any], raw_bytes: bytes) -> dict[str, Any]:
    expectations = sample["expectations"]
    file_name = f"{sample['sample_id']}.{sample['message_format']}"
    return {
        "sample_id": sample["sample_id"],
        "family_id": sample["family_id"],
        "split": sample["split"],
        "scenario": sample["scenario"],
        "message_format": sample["message_format"],
        "file_name": file_name,
        "relative_path": f"samples/{file_name}",
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "mailbox_domain": sample["mailbox_domain"],
        "disposition": expectations["disposition"],
        "classification_code": expectations.get("classification_code"),
        "expected_auth": expectations["expected_auth"],
        "expected_attack_techniques": expectations.get("expected_attack_techniques", []),
        "expected_attachment_names": expectations.get("expected_attachment_names", []),
        "expected_url_domains": expectations.get("expected_url_domains", {"observed": [], "resolved": []}),
        "expected_lookalikes": expectations.get("expected_lookalikes", []),
        "risk_min": expectations.get("risk_min", 0),
        "notes": expectations.get("notes", ""),
    }


def generate_corpus(spec_path: Path, output_root: Path) -> dict[str, Any]:
    spec = load_spec(spec_path)
    samples_dir = output_root / "samples"
    expected_dir = output_root / "expected"
    splits_dir = output_root / "splits"
    samples_dir.mkdir(parents=True, exist_ok=True)
    expected_dir.mkdir(parents=True, exist_ok=True)
    splits_dir.mkdir(parents=True, exist_ok=True)

    source_root = spec_path.parent.parent
    for file_name in ("redirect-fixtures.json", "manifest.schema.json", "README.md"):
        source_path = source_root / file_name
        destination_path = output_root / file_name
        if source_path.exists() and source_path.resolve() != destination_path.resolve():
            shutil.copyfile(source_path, destination_path)
    attachments_readme = source_root / "attachments" / "README.md"
    if attachments_readme.exists():
        (output_root / "attachments").mkdir(parents=True, exist_ok=True)
        destination_path = output_root / "attachments" / "README.md"
        if attachments_readme.resolve() != destination_path.resolve():
            shutil.copyfile(attachments_readme, destination_path)

    manifest_samples: list[dict[str, Any]] = []
    split_members: dict[str, list[str]] = {}
    clustering_ids: list[str] = []

    for sample in spec["samples"]:
        raw_bytes = materialize_sample(sample)
        file_name = f"{sample['sample_id']}.{sample['message_format']}"
        sample_path = samples_dir / file_name
        sample_path.write_bytes(raw_bytes)

        manifest_entry = _manifest_entry(sample, raw_bytes)
        manifest_samples.append(manifest_entry)
        split_members.setdefault(sample["split"], []).append(sample["sample_id"])

        urls = extract_urls(sample["message"].get("body_text"), sample["message"].get("body_html"))
        if sample["family_id"] not in {"benign_internal_control", "benign_vendor_control"} and (
            urls or sample["expectations"].get("expected_attachment_names")
        ):
            clustering_ids.append(sample["sample_id"])

        expected_payload = {
            "sample_id": sample["sample_id"],
            "family_id": sample["family_id"],
            "mailbox_domain": sample["mailbox_domain"],
            "expectations": sample["expectations"],
        }
        (expected_dir / f"{sample['sample_id']}.json").write_text(
            json.dumps(expected_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    manifest = {
        "dataset_name": spec["dataset_name"],
        "dataset_version": spec["dataset_version"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator_version": spec.get("generator_version", GENERATOR_VERSION),
        "sample_count": len(manifest_samples),
        "samples": manifest_samples,
    }

    (output_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for split_name, sample_ids in split_members.items():
        (splits_dir / f"{split_name}.json").write_text(
            json.dumps({"split": split_name, "sample_ids": sorted(sample_ids)}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    (splits_dir / "clustering.json").write_text(
        json.dumps({"split": "clustering", "sample_ids": sorted(clustering_ids)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the Triagent synthetic-corpus scaffold.")
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC_PATH, help="Path to the source scenario catalog.")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="Directory that should receive the generated manifest, samples, and expected outputs.",
    )
    args = parser.parse_args()

    manifest = generate_corpus(args.spec, args.output_root)
    print(
        f"Generated {manifest['sample_count']} synthetic samples in "
        f"{args.output_root.relative_to(REPO_ROOT) if args.output_root.is_relative_to(REPO_ROOT) else args.output_root}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

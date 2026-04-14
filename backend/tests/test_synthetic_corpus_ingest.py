from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings
from app.services.analysis import calculate_risk, extract_urls
from app.services.attack_mapping import AttackMappingInput, build_attack_mapping
from app.services.auth_summary import build_auth_summary, _lookup_ptr_record, _lookup_txt_records
from app.services.eml_parser import parse_eml
from app.services.evidence_export import (
    EvidenceAttachment,
    EvidenceAuditEvent,
    EvidenceBundle,
    EvidenceExportService,
    EvidenceOriginalMessage,
    EvidenceResolution,
    EvidenceUrl,
    EvidenceUrlHop,
    _build_iocs,
    extract_email_domain,
)
from app.services.url_resolution import build_url_analysis, extract_url_domain

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPO_ROOT / "test_data" / "synthetic-corpus"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _build_fixture_fetcher(fixtures: dict[str, list[dict[str, Any]]]):
    by_url: dict[str, dict[str, Any]] = {}
    for chain in fixtures.values():
        for step in chain:
            by_url[step["url"]] = {
                "status_code": step["status_code"],
                "location": step.get("location"),
            }

    def fetch(url: str) -> dict[str, Any]:
        if url not in by_url:
            raise RuntimeError(f"Missing redirect fixture for {url}")
        return dict(by_url[url])

    return fetch


def _status_for_disposition(disposition: str) -> str:
    return "PHISHING" if disposition == "MALICIOUS" else "BENIGN"


def _to_evidence_url(item: dict[str, Any]) -> EvidenceUrl:
    return EvidenceUrl(
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


class SyntheticCorpusIngestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["AUTH_DNS_ENABLED"] = "false"
        get_settings.cache_clear()
        _lookup_txt_records.cache_clear()
        _lookup_ptr_record.cache_clear()

        cls.manifest = _load_json(CORPUS_ROOT / "manifest.json")
        cls.samples_by_id = {item["sample_id"]: item for item in cls.manifest["samples"]}
        cls.gold_split = _load_json(CORPUS_ROOT / "splits" / "gold.json")["sample_ids"]
        fixtures_payload = _load_json(CORPUS_ROOT / "redirect-fixtures.json")
        cls.fetcher = _build_fixture_fetcher(fixtures_payload["fixtures"])

    def test_gold_samples_match_manifest_and_exports(self):
        export_service = EvidenceExportService(None)

        for report_id, sample_id in enumerate(self.gold_split, start=1):
            entry = self.samples_by_id[sample_id]
            with self.subTest(sample_id=sample_id):
                bundle, parsed_report = self._build_bundle(report_id, entry)

                self.assertIsNotNone(parsed_report.get("subject"))
                self.assertIsNotNone(parsed_report.get("from_addr"))

                expected_auth = entry["expected_auth"]
                self.assertEqual(bundle.auth_summary["overview"]["spf"], expected_auth["spf"])
                self.assertEqual(bundle.auth_summary["overview"]["dkim"], expected_auth["dkim"])
                self.assertEqual(bundle.auth_summary["overview"]["dmarc"], expected_auth["dmarc"])

                observed_domains = sorted({domain for domain in (extract_url_domain(url) for url in bundle.urls) if domain})
                resolved_domains = sorted({item.final_domain for item in bundle.url_analysis if item.final_domain})
                self.assertEqual(observed_domains, sorted(entry["expected_url_domains"]["observed"]))
                self.assertEqual(resolved_domains, sorted(entry["expected_url_domains"]["resolved"]))
                self.assertEqual(
                    sorted(item.filename for item in bundle.attachments if item.filename),
                    sorted(entry.get("expected_attachment_names", [])),
                )

                actual_techniques = sorted(item.technique_id for item in bundle.attack_mapping.techniques)
                self.assertEqual(actual_techniques, sorted(entry["expected_attack_techniques"]))

                report_json = json.loads(export_service.render_report_json(bundle).decode("utf-8"))
                ioc_json = json.loads(export_service.render_ioc_json(bundle).decode("utf-8"))
                markdown = export_service.render_markdown(bundle)
                pdf_bytes = export_service.render_pdf(bundle)
                ioc_csv = export_service.render_ioc_csv(bundle).decode("utf-8")

                self.assertEqual(report_json["schema_version"], "triagent.investigation_bundle.v1")
                self.assertEqual(report_json["report"]["classification_code"], entry["classification_code"])
                self.assertEqual(
                    sorted(item["technique_id"] for item in report_json["attack_mapping"]["techniques"]),
                    sorted(entry["expected_attack_techniques"]),
                )
                self.assertEqual(
                    sorted(report_json["artifacts"]["url_domains"]),
                    sorted(
                        {
                            *entry["expected_url_domains"]["observed"],
                            *entry["expected_url_domains"]["resolved"],
                        }
                    ),
                )

                actual_iocs = {(item["type"], item["value"]) for item in ioc_json["iocs"]}
                for domain in entry["expected_url_domains"]["observed"]:
                    self.assertIn(("domain", domain), actual_iocs)
                for domain in entry["expected_url_domains"]["resolved"]:
                    self.assertIn(("domain", domain), actual_iocs)
                for filename in entry.get("expected_attachment_names", []):
                    self.assertIn(("file_name", filename), actual_iocs)

                csv_rows = list(csv.DictReader(ioc_csv.splitlines()))
                self.assertEqual(len(csv_rows), len(ioc_json["iocs"]))

                self.assertIn(bundle.subject or "", markdown)
                self.assertIn("Triagent Evidence Report", markdown)
                self.assertTrue(pdf_bytes.startswith(b"%PDF"))
                self.assertGreater(len(pdf_bytes), 100)

    def _build_bundle(self, report_id: int, entry: dict[str, Any]) -> tuple[EvidenceBundle, dict[str, Any]]:
        sample_path = CORPUS_ROOT / entry["relative_path"]
        raw_bytes = sample_path.read_bytes()
        parsed_report, parsed_attachments = parse_eml(raw_bytes)

        fake_report = SimpleNamespace(
            headers_json=parsed_report.get("headers_json") or {},
            return_path=parsed_report.get("return_path"),
            originating_ip=parsed_report.get("originating_ip"),
            originating_rdns=parsed_report.get("originating_rdns"),
            from_addr=parsed_report.get("from_addr"),
        )
        auth_summary = build_auth_summary(fake_report)

        urls = extract_urls(parsed_report.get("body_text"), parsed_report.get("body_html"))
        url_analysis_payload = build_url_analysis(urls, resolve_urls=True, fetcher=type(self).fetcher)
        url_analysis = [_to_evidence_url(item) for item in url_analysis_payload]
        resolved_urls = [item.final_url for item in url_analysis if item.final_url]
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
        received_at = parsed_report.get("date")
        if received_at is None:
            received_at = datetime.now(timezone.utc)

        attachments = [
            EvidenceAttachment(
                filename=item.filename,
                content_type=item.content_type,
                size_bytes=len(item.data),
                sha256=hashlib.sha256(item.data).hexdigest(),
                s3_key=None,
                created_at=received_at,
            )
            for item in parsed_attachments
        ]

        attack_mapping = build_attack_mapping(
            AttackMappingInput(
                classification_code=entry.get("classification_code"),
                status=_status_for_disposition(entry["disposition"]),
                from_addr=parsed_report.get("from_addr"),
                reply_to=list(parsed_report.get("reply_to") or []),
                return_path=parsed_report.get("return_path"),
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

        bundle = EvidenceBundle(
            report_id=report_id,
            subject=parsed_report.get("subject"),
            ingest_source="UPLOAD",
            generated_at=datetime.now(timezone.utc),
            created_at=received_at,
            received_at=received_at,
            risk_score=calculate_risk(
                subject=parsed_report.get("subject"),
                body_text=parsed_report.get("body_text"),
                from_addr=parsed_report.get("from_addr"),
                mailbox_domain=entry.get("mailbox_domain"),
                urls=urls,
                resolved_urls=resolved_urls,
                from_display_name=parsed_report.get("from_display_name"),
            ),
            status=_status_for_disposition(entry["disposition"]),
            disposition=entry["disposition"],
            classification_code=entry.get("classification_code"),
            rationale_note=None,
            resolved_at=None,
            last_resolved_by=None,
            campaign_id=None,
            campaign_assignment_method=None,
            campaign_assignment_score=None,
            from_addr=parsed_report.get("from_addr"),
            from_domain=extract_email_domain(parsed_report.get("from_addr")),
            reply_to=list(parsed_report.get("reply_to") or []),
            return_path=parsed_report.get("return_path"),
            return_path_domain=extract_email_domain(parsed_report.get("return_path")),
            originating_ip=parsed_report.get("originating_ip"),
            message_id=parsed_report.get("message_id"),
            auth_summary=auth_summary,
            original_message=EvidenceOriginalMessage(
                filename=entry["file_name"],
                content_type="message/rfc822",
                size_bytes=len(raw_bytes),
                sha256=hashlib.sha256(raw_bytes).hexdigest(),
                storage_key=f"synthetic-corpus/{entry['file_name']}",
            ),
            urls=urls,
            url_domains=url_domains,
            url_analysis=url_analysis,
            attack_mapping=attack_mapping,
            iocs=[],
            flagged_artifacts=[],
            attachments=attachments,
            resolution_history=[
                EvidenceResolution(
                    action="RESOLVE",
                    disposition=entry["disposition"],
                    status_after=_status_for_disposition(entry["disposition"]),
                    classification_code=entry.get("classification_code"),
                    note="Synthetic corpus expectation",
                    actor="synthetic-corpus",
                    created_at=received_at,
                )
            ],
            audit_trail=[
                EvidenceAuditEvent(
                    created_at=received_at,
                    action="REPORT_INGESTED",
                    outcome="SUCCESS",
                    actor="synthetic-corpus",
                    request_id=f"synthetic-{entry['sample_id']}",
                    event_uuid=f"synthetic-{entry['sample_id']}",
                    event_hash=hashlib.sha256(entry["sample_id"].encode("utf-8")).hexdigest(),
                )
            ],
        )
        bundle.iocs = _build_iocs(bundle)
        return bundle, parsed_report


if __name__ == "__main__":
    unittest.main()

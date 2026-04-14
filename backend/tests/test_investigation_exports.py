from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from app.services.attack_mapping import AttackMappingInput, build_attack_mapping
from app.services.evidence_export import (
    EvidenceAuditEvent,
    EvidenceAttachment,
    EvidenceBundle,
    EvidenceExportService,
    EvidenceIoc,
    EvidenceOriginalMessage,
    EvidenceResolution,
    EvidenceUrl,
    EvidenceUrlHop,
    _build_iocs,
)


class InvestigationExportTests(unittest.TestCase):
    def test_attack_mapping_uses_reconnaissance_link_for_credential_harvest(self):
        mapping = build_attack_mapping(
            AttackMappingInput(
                classification_code="CRED_HARV",
                status="PHISHING",
                urls=["https://login.example/reset"],
                url_analysis=[
                    {
                        "original_url": "https://login.example/reset",
                        "normalized_url": "https://login.example/reset",
                        "final_url": "https://evil.example/login",
                        "final_domain": "evil.example",
                        "is_shortener": False,
                        "domain_changed": True,
                        "suspicious_redirect": True,
                    }
                ],
            )
        )

        technique_ids = [item.technique_id for item in mapping.techniques]
        self.assertIn("T1598.003", technique_ids)
        self.assertNotIn("T1566.002", technique_ids)
        technique = next(item for item in mapping.techniques if item.technique_id == "T1598.003")
        self.assertEqual(technique.confidence, "high")

    def test_attack_mapping_combines_spoofing_and_link_delivery(self):
        mapping = build_attack_mapping(
            AttackMappingInput(
                classification_code="SPOOF",
                status="PHISHING",
                from_addr="ceo@corp.example",
                return_path="<mailer@evil.example>",
                urls=["https://evil.example/payroll"],
                url_analysis=[
                    {
                        "original_url": "https://evil.example/payroll",
                        "normalized_url": "https://evil.example/payroll",
                        "final_url": "https://evil.example/payroll",
                        "final_domain": "evil.example",
                        "is_shortener": False,
                        "domain_changed": False,
                        "suspicious_redirect": False,
                    }
                ],
                auth_spf_result="fail",
                auth_dkim_result="fail",
                auth_dmarc_result="fail",
            )
        )

        technique_ids = [item.technique_id for item in mapping.techniques]
        self.assertIn("T1672", technique_ids)
        self.assertIn("T1566.002", technique_ids)
        spoof = next(item for item in mapping.techniques if item.technique_id == "T1672")
        self.assertEqual(spoof.confidence, "high")

    def test_ioc_builder_normalizes_and_flags_resolved_artifacts(self):
        bundle = self._bundle()

        iocs = _build_iocs(bundle)

        domain_ioc = next(item for item in iocs if item.type == "domain" and item.value == "evil.example")
        self.assertIn("resolved_url_domain", domain_ioc.roles)
        self.assertTrue(domain_ioc.flagged_malicious)

        hash_ioc = next(item for item in iocs if item.type == "file_hash_sha256")
        self.assertEqual(hash_ioc.value, "deadbeef")
        self.assertTrue(hash_ioc.flagged_malicious)

    def test_json_bundle_contains_attack_mapping_and_iocs(self):
        service = EvidenceExportService(None)
        bundle = self._bundle()
        content = json.loads(service.render_report_json(bundle).decode("utf-8"))

        self.assertEqual(content["schema_version"], "triagent.investigation_bundle.v1")
        self.assertEqual(content["attack_mapping"]["techniques"][0]["technique_id"], "T1566.002")
        self.assertEqual(content["iocs"][0]["type"], "domain")

    def _bundle(self) -> EvidenceBundle:
        now = datetime(2026, 4, 14, tzinfo=timezone.utc)
        attack_mapping = build_attack_mapping(
            AttackMappingInput(
                classification_code="MAL_URL",
                status="PHISHING",
                urls=["http://bit.ly/invite"],
                url_analysis=[
                    {
                        "original_url": "http://bit.ly/invite",
                        "normalized_url": "http://bit.ly/invite",
                        "final_url": "https://evil.example/login",
                        "final_domain": "evil.example",
                        "is_shortener": True,
                        "domain_changed": True,
                        "suspicious_redirect": True,
                    }
                ],
            )
        )
        bundle = EvidenceBundle(
            report_id=1,
            subject="Invoice review",
            ingest_source="UPLOAD",
            generated_at=now,
            created_at=now,
            received_at=now,
            risk_score=80,
            status="PHISHING",
            disposition="MALICIOUS",
            classification_code="MAL_URL",
            rationale_note="Redirected to phishing page.",
            resolved_at=now,
            last_resolved_by="analyst",
            campaign_id=None,
            campaign_assignment_method=None,
            campaign_assignment_score=None,
            from_addr="alerts@example.com",
            from_domain="example.com",
            reply_to=[],
            return_path="<bounce@example.com>",
            return_path_domain="example.com",
            originating_ip="198.51.100.10",
            message_id="<msg@example.com>",
            auth_summary={
                "overview": {"spf": "fail", "dkim": "fail", "dmarc": "fail", "arc": "unknown"},
                "spf": {"result": "fail"},
                "dkim": {"result": "fail", "signature_count": 0, "signatures": []},
                "dmarc": {"result": "fail"},
                "arc": {"result": "unknown"},
                "raw_headers": {},
            },
            original_message=EvidenceOriginalMessage(
                filename="invoice.eml",
                content_type="message/rfc822",
                size_bytes=1024,
                sha256="abc123",
                storage_key="reports/1/original-message/abc123-invoice.eml",
            ),
            urls=["http://bit.ly/invite"],
            url_domains=["bit.ly", "evil.example"],
            url_analysis=[
                EvidenceUrl(
                    original_url="http://bit.ly/invite",
                    normalized_url="http://bit.ly/invite",
                    initial_domain="bit.ly",
                    final_url="https://evil.example/login",
                    final_domain="evil.example",
                    redirect_count=1,
                    is_shortener=True,
                    used_redirector=True,
                    domain_changed=True,
                    suspicious_redirect=True,
                    resolution_status="resolved",
                    resolution_error=None,
                    redirect_chain=[
                        EvidenceUrlHop(
                            index=1,
                            url="http://bit.ly/invite",
                            domain="bit.ly",
                            status_code=302,
                            location="https://evil.example/login",
                        )
                    ],
                )
            ],
            attack_mapping=attack_mapping,
            iocs=[],
            flagged_artifacts=[
                {"kind": "URL_DOMAIN", "value": "evil.example", "label": "Resolved URL domain - evil.example"},
                {"kind": "ATTACHMENT_SHA256", "value": "deadbeef", "label": "Attachment SHA-256 - deadbeef"},
            ],
            attachments=[
                EvidenceAttachment(
                    filename="invoice.zip",
                    content_type="application/zip",
                    size_bytes=512,
                    sha256="deadbeef",
                    s3_key="reports/1/attachments/deadbeef-invoice.zip",
                    created_at=now,
                )
            ],
            resolution_history=[
                EvidenceResolution(
                    action="RESOLVE",
                    disposition="MALICIOUS",
                    status_after="PHISHING",
                    classification_code="MAL_URL",
                    note="Confirmed phishing",
                    actor="analyst",
                    created_at=now,
                )
            ],
            audit_trail=[
                EvidenceAuditEvent(
                    created_at=now,
                    action="REPORT_INGESTED",
                    outcome="SUCCESS",
                    actor="analyst",
                    request_id="req-1",
                    event_uuid="uuid-1",
                    event_hash="hash-1",
                )
            ],
        )
        bundle.iocs = _build_iocs(bundle)
        return bundle


if __name__ == "__main__":
    unittest.main()

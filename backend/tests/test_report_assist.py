from __future__ import annotations

from pathlib import Path
import sys
import unittest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.models.report import ArtifactKind, ResolutionDisposition
from app.services.report_assist import AssistArtifactOption, ReportAssistInput, build_report_assist_draft


class ReportAssistDraftTests(unittest.TestCase):
    def test_credential_harvest_shortener_produces_malicious_link_draft(self):
        draft = build_report_assist_draft(
            ReportAssistInput(
                report_id=1,
                risk_score=82,
                status="OPEN",
                subject="Password reset required",
                body_excerpt="Your Microsoft 365 password expires today. Sign in to keep access.",
                from_addr="it-support@contoso-mail.example",
                mailbox_domain="contoso.example",
                urls=["http://bit.ly/contoso-reset"],
                url_analysis=[
                    {
                        "original_url": "http://bit.ly/contoso-reset",
                        "final_url": "https://login-help.example/reset",
                        "final_domain": "login-help.example",
                        "domain_changed": True,
                        "is_shortener": True,
                        "suspicious_redirect": True,
                    }
                ],
                auth_summary={
                    "spf": {"result": "fail"},
                    "dkim": {"result": "fail"},
                    "dmarc": {"result": "fail"},
                },
                lookalike_analysis={
                    "matches": [
                        {
                            "field": "from_addr",
                            "observed_domain": "contoso-mail.example",
                            "confidence": "medium",
                        }
                    ]
                },
                artifact_options=[
                    AssistArtifactOption(
                        kind=ArtifactKind.URL,
                        value="http://bit.ly/contoso-reset",
                        label="Message URL - http://bit.ly/contoso-reset",
                    ),
                    AssistArtifactOption(
                        kind=ArtifactKind.URL,
                        value="https://login-help.example/reset",
                        label="Resolved URL - https://login-help.example/reset",
                    ),
                    AssistArtifactOption(
                        kind=ArtifactKind.URL_DOMAIN,
                        value="login-help.example",
                        label="Resolved URL domain - login-help.example",
                    ),
                ],
            ),
        )

        self.assertEqual(draft.recommended_disposition, ResolutionDisposition.MALICIOUS)
        self.assertEqual(draft.recommended_classification_code, "CRED_HARV")
        self.assertTrue(any("url" in reason.lower() or "redirect" in reason.lower() for reason in draft.reasons))
        self.assertTrue(any(item.kind == ArtifactKind.URL_DOMAIN for item in draft.flagged_artifacts))

    def test_finance_impersonation_prefers_fin_fraud(self):
        draft = build_report_assist_draft(
            ReportAssistInput(
                report_id=2,
                risk_score=74,
                status="OPEN",
                subject="Urgent wire payment approval",
                body_excerpt="Please process the attached remittance details before close of business.",
                from_addr="cfo@contoso-secure.example",
                reply_to=["accounts@vendor-payments.example"],
                return_path="<mailer@vendor-payments.example>",
                mailbox_domain="contoso.example",
                auth_summary={
                    "spf": {"result": "fail"},
                    "dkim": {"result": "fail"},
                    "dmarc": {"result": "fail"},
                },
                lookalike_analysis={
                    "matches": [
                        {
                            "field": "from_addr",
                            "observed_domain": "contoso-secure.example",
                            "confidence": "high",
                        }
                    ]
                },
                artifact_options=[
                    AssistArtifactOption(
                        kind=ArtifactKind.FROM_ADDR,
                        value="cfo@contoso-secure.example",
                        label="From email address - cfo@contoso-secure.example",
                    ),
                    AssistArtifactOption(
                        kind=ArtifactKind.REPLY_TO,
                        value="accounts@vendor-payments.example",
                        label="Reply-To - accounts@vendor-payments.example",
                    ),
                    AssistArtifactOption(
                        kind=ArtifactKind.RETURN_PATH,
                        value="<mailer@vendor-payments.example>",
                        label="Return-Path email address - <mailer@vendor-payments.example>",
                    ),
                ],
            ),
        )

        self.assertEqual(draft.recommended_disposition, ResolutionDisposition.MALICIOUS)
        self.assertEqual(draft.recommended_classification_code, "FIN_FRAUD")
        self.assertTrue(any(item.kind == ArtifactKind.FROM_ADDR for item in draft.flagged_artifacts))

    def test_benign_message_produces_safe_draft(self):
        draft = build_report_assist_draft(
            ReportAssistInput(
                report_id=3,
                risk_score=10,
                status="OPEN",
                subject="Quarterly newsletter",
                body_excerpt="This is the regular vendor newsletter with no action required.",
                from_addr="news@vendor.example",
                mailbox_domain="contoso.example",
                auth_summary={
                    "spf": {"result": "pass"},
                    "dkim": {"result": "pass"},
                    "dmarc": {"result": "pass"},
                },
                artifact_options=[],
            ),
        )

        self.assertEqual(draft.recommended_disposition, ResolutionDisposition.SAFE)
        self.assertIsNone(draft.recommended_classification_code)
        self.assertIn("safe", draft.summary.lower())


if __name__ == "__main__":
    unittest.main()

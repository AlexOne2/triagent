from __future__ import annotations

from pathlib import Path
import sys
import unittest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.triage_scoring import ReportTriageInput, build_report_triage_assessment


class ReportTriageScoringTests(unittest.TestCase):
    def test_bulk_newsletter_routes_to_bulk_spam(self):
        assessment = build_report_triage_assessment(
            ReportTriageInput(
                risk_score=18,
                subject="Weekly deals newsletter",
                body_text="Special offer this week. View in browser or unsubscribe at any time.",
                from_addr="news@mailer.vendor.example",
                urls=["https://vendor.example/deals"],
                headers_json={
                    "List-Id": "<deals.vendor.example>",
                    "List-Unsubscribe": "<mailto:unsubscribe@vendor.example>, <https://vendor.example/unsub>",
                    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                    "Precedence": "bulk",
                },
                auth_summary={
                    "spf": {"result": "pass"},
                    "dkim": {"result": "pass"},
                    "dmarc": {"result": "pass"},
                },
            )
        )

        self.assertEqual(assessment.bucket, "BULK_SPAM")
        self.assertGreaterEqual(assessment.bulk_benign_score, 70)
        self.assertLessEqual(assessment.threat_score, 25)
        self.assertFalse(assessment.analyst_worthy)

    def test_credential_harvest_with_auth_failures_routes_to_needs_investigation(self):
        assessment = build_report_triage_assessment(
            ReportTriageInput(
                risk_score=82,
                subject="Password reset required",
                body_text="Your Microsoft 365 password expires today. Sign in to keep access.",
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
            )
        )

        self.assertEqual(assessment.bucket, "NEEDS_INVESTIGATION")
        self.assertGreaterEqual(assessment.threat_score, 65)
        self.assertIn("AUTH_FAILURES", assessment.reason_codes)

    def test_finance_impersonation_routes_to_needs_investigation(self):
        assessment = build_report_triage_assessment(
            ReportTriageInput(
                risk_score=74,
                subject="Urgent wire payment approval",
                body_text="Please process the attached remittance details before close of business.",
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
                            "target_domain": "contoso.example",
                            "confidence": "high",
                        }
                    ]
                },
            )
        )

        self.assertEqual(assessment.bucket, "NEEDS_INVESTIGATION")
        self.assertTrue(assessment.analyst_worthy)
        self.assertGreaterEqual(assessment.investigation_priority_score, 75)

    def test_clean_internal_notice_routes_to_likely_benign(self):
        assessment = build_report_triage_assessment(
            ReportTriageInput(
                risk_score=8,
                subject="IT notice: printer maintenance complete",
                body_text="The scheduled printer maintenance is complete. No action is required.",
                from_addr="it-ops@contoso.example",
                mailbox_domain="contoso.example",
                auth_summary={
                    "spf": {"result": "pass"},
                    "dkim": {"result": "pass"},
                    "dmarc": {"result": "pass"},
                },
            )
        )

        self.assertEqual(assessment.bucket, "LIKELY_BENIGN")
        self.assertLessEqual(assessment.threat_score, 20)
        self.assertFalse(assessment.analyst_worthy)

    def test_finance_language_without_other_signals_does_not_route_to_likely_benign(self):
        assessment = build_report_triage_assessment(
            ReportTriageInput(
                risk_score=12,
                subject="Urgent payment confirmation",
                body_text="Please confirm the wire details and remittance amount today.",
                from_addr="billing@vendor.example",
                mailbox_domain="contoso.example",
                auth_summary={
                    "spf": {"result": "pass"},
                    "dkim": {"result": "pass"},
                    "dmarc": {"result": "pass"},
                },
            )
        )

        self.assertEqual(assessment.bucket, "UNCERTAIN")
        self.assertIn("FINANCE_LANGUAGE", assessment.reason_codes)

    def test_auth_failures_without_bulk_signals_route_to_needs_investigation(self):
        assessment = build_report_triage_assessment(
            ReportTriageInput(
                risk_score=18,
                subject="Scan to restore your mobile access",
                body_text="Restore access to your account immediately.",
                from_addr="mobile-access@webmail-auth.example",
                mailbox_domain="contoso.example",
                auth_summary={
                    "spf": {"result": "fail"},
                    "dkim": {"result": "fail"},
                    "dmarc": {"result": "fail"},
                },
            )
        )

        self.assertEqual(assessment.bucket, "NEEDS_INVESTIGATION")
        self.assertIn("AUTH_FAILURES", assessment.reason_codes)


if __name__ == "__main__":
    unittest.main()

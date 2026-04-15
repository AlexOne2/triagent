from __future__ import annotations

from pathlib import Path
import sys
import unittest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.lookalike_detection import build_lookalike_analysis


class LookalikeDetectionTests(unittest.TestCase):
    def test_detects_brand_affix_against_mailbox_domain(self):
        analysis = build_lookalike_analysis(
            mailbox_domain="contoso.example",
            from_addr="security@contoso-mail.example",
            reply_to=["helpdesk@contoso-mail.example"],
            return_path="<bounce@contoso-mail.example>",
        )

        self.assertIsNotNone(analysis)
        self.assertTrue(analysis["has_suspected_lookalikes"])
        self.assertEqual(
            sorted(
                (item["field"], item["observed_domain"], item["match_type"], item["confidence"])
                for item in analysis["matches"]
            ),
            [
                ("from_addr", "contoso-mail.example", "brand_affix", "medium"),
                ("reply_to", "contoso-mail.example", "brand_affix", "medium"),
                ("return_path", "contoso-mail.example", "brand_affix", "medium"),
            ],
        )

    def test_detects_homoglyph_substitution(self):
        analysis = build_lookalike_analysis(
            mailbox_domain="contoso.example",
            from_addr="security@cont0so.example",
            reply_to=[],
            return_path="<bounce@cont0so.example>",
        )

        self.assertIsNotNone(analysis)
        self.assertEqual(
            sorted((item["field"], item["match_type"], item["confidence"]) for item in analysis["matches"]),
            [
                ("from_addr", "homoglyph", "high"),
                ("return_path", "homoglyph", "high"),
            ],
        )

    def test_detects_deceptive_subdomain(self):
        analysis = build_lookalike_analysis(
            mailbox_domain="contoso.example",
            from_addr="it@contoso.example.login-review.example",
            reply_to=[],
            return_path=None,
        )

        self.assertIsNotNone(analysis)
        self.assertEqual(len(analysis["matches"]), 1)
        self.assertEqual(analysis["matches"][0]["match_type"], "deceptive_subdomain")
        self.assertEqual(analysis["matches"][0]["confidence"], "high")

    def test_does_not_flag_same_org_or_unrelated_domains(self):
        same_org = build_lookalike_analysis(
            mailbox_domain="contoso.example",
            from_addr="it-ops@contoso.example",
            reply_to=["support@contoso.example"],
            return_path="<bounce@contoso.example>",
        )
        unrelated = build_lookalike_analysis(
            mailbox_domain="contoso.example",
            from_addr="billing@vendor.example",
            reply_to=[],
            return_path=None,
        )

        self.assertIsNotNone(same_org)
        self.assertFalse(same_org["has_suspected_lookalikes"])
        self.assertEqual(same_org["matches"], [])
        self.assertIsNotNone(unrelated)
        self.assertFalse(unrelated["has_suspected_lookalikes"])
        self.assertEqual(unrelated["matches"], [])


if __name__ == "__main__":
    unittest.main()

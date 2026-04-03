from __future__ import annotations

import unittest

from app.models.report import Report, ReportStatus
from app.services.auth_summary import build_auth_summary


def make_report(headers_json=None, **overrides) -> Report:
    payload = {
        "risk_score": 0,
        "status": ReportStatus.OPEN,
        "headers_json": headers_json or {},
        "from_addr": "alerts@example.com",
        "return_path": "<mailer@example.com>",
        "originating_ip": "203.0.113.10",
        "originating_rdns": "mx.example.net",
    }
    payload.update(overrides)
    return Report(**payload)


class AuthSummaryTests(unittest.TestCase):
    def test_google_style_authentication_results(self):
        report = make_report(
            headers_json={
                "Authentication-Results": (
                    "mx.google.com; spf=pass smtp.mailfrom=chef-treff.de; "
                    "dkim=pass header.i=@chef-treff.de header.s=google header.d=chef-treff.de "
                    "header.a=rsa-sha256 header.c=relaxed/relaxed; "
                    "dmarc=pass header.from=chef-treff.de"
                )
            },
            from_addr="emilio@chef-treff.de",
            return_path="<emilio@chef-treff.de>",
        )

        summary = build_auth_summary(report)
        self.assertEqual(summary["overview"]["spf"], "pass")
        self.assertEqual(summary["overview"]["dkim"], "pass")
        self.assertEqual(summary["overview"]["dmarc"], "pass")
        self.assertEqual(summary["spf"]["smtp_mailfrom"], "chef-treff.de")
        self.assertEqual(summary["dkim"]["signature_count"], 1)
        self.assertEqual(summary["dkim"]["signatures"][0]["selector"], "google")
        self.assertEqual(summary["dmarc"]["header_from"], "chef-treff.de")

    def test_dmarc_fail_with_header_from(self):
        report = make_report(
            headers_json={
                "Authentication-Results": (
                    "outlook.office365.com; spf=pass smtp.mailfrom=evil-mailer.com; "
                    "dkim=fail header.i=@evil-mailer.com header.s=k1 header.d=evil-mailer.com; "
                    "dmarc=fail action=oreject header.from=company.com"
                )
            },
            from_addr="ceo@company.com",
            return_path="<mailer@evil-mailer.com>",
        )

        summary = build_auth_summary(report)
        self.assertEqual(summary["overview"]["dmarc"], "fail")
        self.assertEqual(summary["dmarc"]["header_from"], "company.com")
        self.assertEqual(summary["dmarc"]["aligned_mailfrom_domain"], "evil-mailer.com")

    def test_multiple_dkim_signatures(self):
        report = make_report(
            headers_json={
                "Authentication-Results": (
                    "mx.example.net; "
                    "dkim=pass header.i=@example.com header.s=selector1 header.d=example.com header.a=rsa-sha256; "
                    "dkim=fail header.i=@mailer.example.net header.s=selector2 header.d=mailer.example.net header.a=rsa-sha256; "
                    "spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com"
                )
            }
        )

        summary = build_auth_summary(report)
        self.assertEqual(summary["dkim"]["signature_count"], 2)
        self.assertEqual(summary["dkim"]["signatures"][1]["result"], "fail")
        self.assertEqual(summary["dkim"]["signatures"][1]["signing_domain"], "mailer.example.net")

    def test_received_spf_without_authentication_results(self):
        report = make_report(
            headers_json={
                "Received-SPF": "pass (example.net: domain of sender@example.com designates 203.0.113.20 as permitted sender) client-ip=203.0.113.20;"
            },
            return_path="<sender@example.com>",
            originating_ip="203.0.113.20",
        )

        summary = build_auth_summary(report)
        self.assertEqual(summary["overview"]["spf"], "pass")
        self.assertEqual(summary["overview"]["dkim"], "unknown")
        self.assertEqual(summary["spf"]["source_header"], "Received-SPF")
        self.assertEqual(summary["spf"]["originating_ip"], "203.0.113.20")

    def test_arc_headers_are_exposed(self):
        report = make_report(
            headers_json={
                "Authentication-Results": "mx.example.net; arc=pass",
                "ARC-Authentication-Results": "i=1; mx.example.net; dkim=pass header.i=@example.com",
                "ARC-Seal": "i=1; a=rsa-sha256; cv=pass; d=example.com; s=arcselector1; b=abc123",
                "ARC-Message-Signature": "i=1; a=rsa-sha256; d=example.com; s=arcselector1; c=relaxed/relaxed; b=def456",
            }
        )

        summary = build_auth_summary(report)
        self.assertEqual(summary["overview"]["arc"], "pass")
        self.assertEqual(summary["arc"]["instance"], "1")
        self.assertEqual(summary["arc"]["seal_result"], "pass")

    def test_missing_headers_gracefully_fall_back_to_unknown(self):
        summary = build_auth_summary(make_report(headers_json={}))
        self.assertEqual(summary["overview"]["spf"], "unknown")
        self.assertEqual(summary["overview"]["dkim"], "unknown")
        self.assertEqual(summary["overview"]["dmarc"], "unknown")
        self.assertEqual(summary["overview"]["arc"], "unknown")


if __name__ == "__main__":
    unittest.main()

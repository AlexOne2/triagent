from __future__ import annotations

import unittest

from app.api.routes import _available_artifacts
from app.models.report import ArtifactKind, Report, ReportStatus
from app.services.url_resolution import analyze_url, build_url_analysis


class UrlResolutionTests(unittest.TestCase):
    def test_analyze_url_records_redirect_chain_and_final_domain(self):
        steps = {
            "http://bit.ly/invite": {"status_code": 302, "location": "https://1drv.ms/u/s!abc"},
            "https://1drv.ms/u/s!abc": {"status_code": 302, "location": "https://evil.example/login"},
            "https://evil.example/login": {"status_code": 200, "location": None},
        }

        analysis = analyze_url(
            "http://bit.ly/invite",
            resolve_urls=True,
            fetcher=lambda current: steps[current],
        )

        self.assertEqual(analysis["final_url"], "https://evil.example/login")
        self.assertEqual(analysis["final_domain"], "evil.example")
        self.assertEqual(analysis["redirect_count"], 2)
        self.assertTrue(analysis["is_shortener"])
        self.assertTrue(analysis["domain_changed"])
        self.assertTrue(analysis["suspicious_redirect"])
        self.assertEqual(analysis["resolution_status"], "resolved")
        self.assertEqual(len(analysis["redirect_chain"]), 3)
        self.assertEqual(analysis["redirect_chain"][0]["location"], "https://1drv.ms/u/s!abc")

    def test_build_url_analysis_can_skip_network_resolution(self):
        analysis = build_url_analysis(["https://example.com/reset"], resolve_urls=False)

        self.assertEqual(len(analysis), 1)
        self.assertEqual(analysis[0]["final_url"], "https://example.com/reset")
        self.assertEqual(analysis[0]["resolution_status"], "disabled")
        self.assertEqual(analysis[0]["redirect_chain"], [])

    def test_available_artifacts_include_resolved_final_url_and_domain(self):
        analysis = {
            "original_url": "http://bit.ly/invite",
            "normalized_url": "http://bit.ly/invite",
            "initial_domain": "bit.ly",
            "final_url": "https://evil.example/login",
            "final_domain": "evil.example",
            "redirect_count": 1,
            "is_shortener": True,
            "used_redirector": True,
            "domain_changed": True,
            "suspicious_redirect": True,
            "resolution_status": "resolved",
            "resolution_error": None,
            "redirect_chain": [],
        }
        report = Report(
            id=1,
            urls_json=["http://bit.ly/invite"],
            url_analysis_json=[analysis],
            status=ReportStatus.OPEN,
        )

        available = _available_artifacts(report)

        self.assertIn("https://evil.example/login", available[ArtifactKind.URL])
        self.assertIn("evil.example", available[ArtifactKind.URL_DOMAIN])


if __name__ == "__main__":
    unittest.main()

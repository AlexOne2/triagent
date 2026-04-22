from __future__ import annotations

import unittest

from app.api.routes import _available_artifacts
from app.core.config import get_settings
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
        self.assertIn("redirector_origin", analysis["redirect_risk_reasons"])
        self.assertIn("credential_url_signals", analysis["redirect_risk_reasons"])
        self.assertEqual(analysis["resolution_status"], "resolved")
        self.assertEqual(len(analysis["redirect_chain"]), 3)
        self.assertEqual(analysis["redirect_chain"][0]["location"], "https://1drv.ms/u/s!abc")

    def test_analyze_url_does_not_flag_benign_social_share_redirect_as_suspicious(self):
        steps = {
            "https://luma.com/social-share?m=join-event&n=Infoabend&pa=ahs7n9xa&p=fb": {
                "status_code": 302,
                "location": "https://www.facebook.com/share_channel/?type=reshare&link=https%3A%2F%2Fluma.com%2Fahs7n9xa",
            },
            "https://www.facebook.com/share_channel/?type=reshare&link=https%3A%2F%2Fluma.com%2Fahs7n9xa": {
                "status_code": 200,
                "location": None,
            },
        }

        analysis = analyze_url(
            "https://luma.com/social-share?m=join-event&n=Infoabend&pa=ahs7n9xa&p=fb",
            resolve_urls=True,
            fetcher=lambda current: steps[current],
        )

        self.assertEqual(analysis["final_domain"], "www.facebook.com")
        self.assertTrue(analysis["domain_changed"])
        self.assertEqual(analysis["redirect_count"], 1)
        self.assertFalse(analysis["suspicious_redirect"])
        self.assertEqual(analysis["redirect_risk_score"], 0)
        self.assertEqual(analysis["redirect_risk_reasons"], [])

    def test_build_url_analysis_can_skip_network_resolution(self):
        analysis = build_url_analysis(["https://example.com/reset"], resolve_urls=False)

        self.assertEqual(len(analysis), 1)
        self.assertEqual(analysis[0]["final_url"], "https://example.com/reset")
        self.assertEqual(analysis[0]["resolution_status"], "disabled")
        self.assertEqual(analysis[0]["redirect_chain"], [])

    def test_build_url_analysis_has_no_default_per_report_url_cap(self):
        urls = [f"https://example.com/item/{index}" for index in range(30)]

        analysis = build_url_analysis(urls, resolve_urls=False)

        self.assertEqual(len(analysis), 30)
        self.assertTrue(all(item["resolution_status"] == "disabled" for item in analysis))

    def test_build_url_analysis_can_still_apply_optional_cap_when_configured(self):
        settings = get_settings().model_copy(update={"url_resolution_max_urls": 1})

        analysis = build_url_analysis(
            ["https://example.com/a", "https://example.com/b"],
            resolve_urls=False,
            settings=settings,
        )

        self.assertEqual(analysis[0]["resolution_status"], "disabled")
        self.assertEqual(analysis[1]["resolution_status"], "skipped_limit")
        self.assertEqual(analysis[1]["resolution_error"], "Skipped after 1 URLs")

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

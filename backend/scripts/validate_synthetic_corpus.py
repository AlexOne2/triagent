from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.analysis import URL_SHORTENERS, calculate_risk, extract_urls
from app.services.attack_mapping import AttackMappingInput, build_attack_mapping
from app.services.eml_parser import parse_eml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS_ROOT = REPO_ROOT / "test_data" / "synthetic-corpus"


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


def _extract_url_domain(url: str) -> str | None:
    if not url:
        return None
    parsed = urlsplit(url)
    if not parsed.hostname:
        return None
    return parsed.hostname.lower()


def _registrable_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    parts = [item for item in domain.lower().split(".") if item]
    if len(parts) <= 2:
        return ".".join(parts) or None
    return ".".join(parts[-2:])


def _build_url_analysis(urls: list[str], fetcher) -> list[dict[str, Any]]:
    analyses: list[dict[str, Any]] = []
    for original_url in urls:
        current = original_url
        initial_domain = _extract_url_domain(current)
        redirect_chain: list[dict[str, Any]] = []
        seen: set[str] = set()

        while True:
            if current in seen:
                redirect_chain.append(
                    {
                        "index": len(redirect_chain) + 1,
                        "url": current,
                        "domain": _extract_url_domain(current),
                        "status_code": None,
                        "location": None,
                    }
                )
                break
            seen.add(current)

            step = fetcher(current)
            redirect_chain.append(
                {
                    "index": len(redirect_chain) + 1,
                    "url": current,
                    "domain": _extract_url_domain(current),
                    "status_code": step.get("status_code"),
                    "location": step.get("location"),
                }
            )
            if not step.get("location"):
                break
            current = step["location"]

        final_url = current
        final_domain = _extract_url_domain(final_url)
        analyses.append(
            {
                "original_url": original_url,
                "normalized_url": original_url,
                "initial_domain": initial_domain,
                "final_url": final_url,
                "final_domain": final_domain,
                "redirect_count": sum(1 for item in redirect_chain if item.get("location")),
                "is_shortener": bool(initial_domain and initial_domain in URL_SHORTENERS),
                "used_redirector": len(redirect_chain) > 1,
                "domain_changed": _registrable_domain(initial_domain) != _registrable_domain(final_domain),
                "suspicious_redirect": len(redirect_chain) > 1 and _registrable_domain(initial_domain) != _registrable_domain(final_domain),
                "resolution_status": "resolved" if len(redirect_chain) > 1 else "no_redirect",
                "resolution_error": None,
                "redirect_chain": redirect_chain,
            }
        )
    return analyses


def _extract_auth_status(headers: dict[str, Any], method: str) -> str:
    blob = None
    for key, value in headers.items():
        if key.lower() == "authentication-results":
            blob = value
            break
    if blob is None:
        return "unknown"
    if isinstance(blob, list):
        blob = " ".join(str(item) for item in blob)
    text = str(blob).lower()
    needle = f"{method.lower()}="
    index = text.find(needle)
    if index < 0:
        return "unknown"
    remainder = text[index + len(needle):]
    status = remainder.split()[0].split(";", 1)[0].strip()
    return status or "unknown"


def validate_corpus(root: Path) -> list[str]:
    manifest = _load_json(root / "manifest.json")
    expected_count = manifest.get("sample_count")
    samples = manifest.get("samples", [])
    errors: list[str] = []

    if expected_count != len(samples):
        errors.append(f"manifest sample_count={expected_count} does not match samples length={len(samples)}")

    fixtures_payload = _load_json(root / "redirect-fixtures.json")
    fetcher = _build_fixture_fetcher(fixtures_payload.get("fixtures", {}))
    seen_ids: set[str] = set()
    for entry in samples:
        sample_id = entry["sample_id"]
        if sample_id in seen_ids:
            errors.append(f"{sample_id}: duplicate sample_id in manifest")
            continue
        seen_ids.add(sample_id)

        sample_path = root / entry["relative_path"]
        if not sample_path.exists():
            errors.append(f"{sample_id}: missing sample file {entry['relative_path']}")
            continue

        raw_bytes = sample_path.read_bytes()
        parsed_report, parsed_attachments = parse_eml(raw_bytes)
        urls = extract_urls(parsed_report.get("body_text"), parsed_report.get("body_html"))
        observed_domains = sorted({domain for domain in (_extract_url_domain(url) for url in urls) if domain})

        headers = parsed_report.get("headers_json") or {}
        auth_summary = {
            "overview": {
                "spf": _extract_auth_status(headers, "spf"),
                "dkim": _extract_auth_status(headers, "dkim"),
                "dmarc": _extract_auth_status(headers, "dmarc"),
            }
        }

        url_analysis = _build_url_analysis(urls, fetcher=fetcher)
        resolved_domains = sorted({item["final_domain"] for item in url_analysis if item.get("final_domain")})
        risk_score = calculate_risk(
            subject=parsed_report.get("subject"),
            body_text=parsed_report.get("body_text"),
            from_addr=parsed_report.get("from_addr"),
            mailbox_domain=entry.get("mailbox_domain"),
            urls=urls,
            resolved_urls=[item["final_url"] for item in url_analysis if item.get("final_url")],
            from_display_name=parsed_report.get("from_display_name"),
        )

        expected_auth = entry["expected_auth"]
        for key in ("spf", "dkim", "dmarc"):
            actual = auth_summary["overview"].get(key)
            if actual != expected_auth.get(key):
                errors.append(f"{sample_id}: expected {key}={expected_auth.get(key)} but got {actual}")

        expected_observed_domains = sorted(entry.get("expected_url_domains", {}).get("observed", []))
        if expected_observed_domains != observed_domains:
            errors.append(
                f"{sample_id}: expected observed domains {expected_observed_domains} but got {observed_domains}"
            )

        expected_resolved_domains = sorted(entry.get("expected_url_domains", {}).get("resolved", []))
        if expected_resolved_domains != resolved_domains:
            errors.append(
                f"{sample_id}: expected resolved domains {expected_resolved_domains} but got {resolved_domains}"
            )

        expected_attachments = sorted(entry.get("expected_attachment_names", []))
        actual_attachments = sorted(item.filename for item in parsed_attachments)
        if expected_attachments != actual_attachments:
            errors.append(
                f"{sample_id}: expected attachments {expected_attachments} but got {actual_attachments}"
            )

        if risk_score < int(entry.get("risk_min", 0)):
            errors.append(f"{sample_id}: risk score {risk_score} is below expected minimum {entry.get('risk_min')}")

        attack_mapping = build_attack_mapping(
            AttackMappingInput(
                classification_code=entry.get("classification_code"),
                status="PHISHING" if entry["disposition"] == "MALICIOUS" else "BENIGN",
                from_addr=parsed_report.get("from_addr"),
                reply_to=parsed_report.get("reply_to") or [],
                return_path=parsed_report.get("return_path"),
                urls=urls,
                url_analysis=url_analysis,
                attachment_names=actual_attachments,
                auth_spf_result=auth_summary["overview"].get("spf"),
                auth_dkim_result=auth_summary["overview"].get("dkim"),
                auth_dmarc_result=auth_summary["overview"].get("dmarc"),
            )
        )
        actual_techniques = sorted(item.technique_id for item in attack_mapping.techniques)
        expected_techniques = sorted(entry.get("expected_attack_techniques", []))
        if expected_techniques != actual_techniques:
            errors.append(
                f"{sample_id}: expected ATT&CK techniques {expected_techniques} but got {actual_techniques}"
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the generated Triagent synthetic corpus.")
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=DEFAULT_CORPUS_ROOT,
        help="Root directory of the generated synthetic corpus.",
    )
    args = parser.parse_args()

    errors = validate_corpus(args.corpus_root)
    if errors:
        print("Synthetic corpus validation failed:")
        for item in errors:
            print(f"- {item}")
        return 1

    print(f"Validated synthetic corpus at {args.corpus_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

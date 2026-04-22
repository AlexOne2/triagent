from __future__ import annotations

import ipaddress
import ssl
from typing import Any, Callable, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, unquote_plus, urljoin, urlsplit
from urllib.request import HTTPHandler, HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from app.core.config import Settings, get_settings
from app.services.analysis import SUSPICIOUS_TLDS, URL_SHORTENERS

KNOWN_REDIRECTOR_SUFFIXES = {
    "1drv.ms",
    "onedrive.live.com",
    "safelinks.protection.outlook.com",
    "urldefense.com",
}
BENIGN_SHARE_DESTINATION_SUFFIXES = {
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
}
BENIGN_SHARE_PATH_MARKERS = (
    "/dialog/share",
    "/intent/tweet",
    "/share",
    "/share_channel",
    "/sharearticle",
    "/sharing/share-offsite",
    "/sharer",
)
CREDENTIAL_URL_KEYWORDS = {
    "account",
    "auth",
    "credential",
    "login",
    "logon",
    "mfa",
    "oauth",
    "password",
    "reset",
    "secure",
    "session",
    "signin",
    "token",
    "unlock",
    "validate",
    "verify",
    "webmail",
}
RISKY_QUERY_KEYS = {
    "continue",
    "email",
    "login_hint",
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "return_to",
    "session",
    "token",
    "user",
}
MULTIPART_PUBLIC_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.mx",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
}

UrlFetcher = Callable[[str], dict[str, Any]]


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def extract_url_domain(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    parsed = urlsplit(cleaned if "://" in cleaned else f"//{cleaned}", scheme="http")
    if not parsed.hostname:
        return None
    return parsed.hostname.lower()


def is_shortener_domain(domain: str | None) -> bool:
    if not domain:
        return False
    lowered = domain.lower()
    return any(lowered == item or lowered.endswith(f".{item}") for item in URL_SHORTENERS)


def is_known_redirector(domain: str | None) -> bool:
    if not domain:
        return False
    lowered = domain.lower()
    if is_shortener_domain(lowered):
        return True
    return any(lowered == suffix or lowered.endswith(f".{suffix}") for suffix in KNOWN_REDIRECTOR_SUFFIXES)


def registrable_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    parts = [item for item in domain.lower().split(".") if item]
    if len(parts) <= 2:
        return ".".join(parts) or None
    last_two = ".".join(parts[-2:])
    if last_two in MULTIPART_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalize_url(value: str) -> str:
    return value.strip().strip("'\"()[]{}.,;:")


def _is_ip_literal_host(domain: str | None) -> bool:
    if not domain:
        return False
    try:
        ipaddress.ip_address(domain.strip("[]"))
    except ValueError:
        return False
    return True


def _has_punycode_label(domain: str | None) -> bool:
    if not domain:
        return False
    return any(part.startswith("xn--") for part in domain.lower().split("."))


def _has_suspicious_tld(domain: str | None) -> bool:
    registrable = registrable_domain(domain)
    if not registrable or "." not in registrable:
        return False
    return registrable.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS


def _has_unusual_host_shape(domain: str | None) -> bool:
    registrable = registrable_domain(domain)
    if not registrable or "." not in registrable:
        return False
    label = registrable.split(".", 1)[0]
    if len(label) >= 24:
        return True
    if label.count("-") >= 2:
        return True
    digit_count = sum(1 for char in label if char.isdigit())
    return bool(label) and digit_count / len(label) >= 0.35


def _url_keyword_blob(url: str | None) -> str:
    if not url:
        return ""
    parsed = urlsplit(url)
    parts = [parsed.path or "", parsed.query or "", parsed.fragment or ""]
    return unquote_plus(" ".join(parts)).lower()


def _has_credential_url_signals(url: str | None) -> bool:
    if not url:
        return False
    text = _url_keyword_blob(url)
    if any(keyword in text for keyword in CREDENTIAL_URL_KEYWORDS):
        return True

    parsed = urlsplit(url)
    return any(key.lower() in RISKY_QUERY_KEYS for key, _ in parse_qsl(parsed.query, keep_blank_values=True))


def _is_benign_share_destination(url: str | None, domain: str | None) -> bool:
    registrable = registrable_domain(domain)
    if not registrable or registrable not in BENIGN_SHARE_DESTINATION_SUFFIXES:
        return False
    path = (urlsplit(url).path or "").lower() if url else ""
    return any(marker in path for marker in BENIGN_SHARE_PATH_MARKERS)


def _redirect_risk_reasons(
    *,
    final_url: str | None,
    initial_domain: str | None,
    final_domain: str | None,
    redirect_chain: Sequence[dict[str, Any]],
    redirect_count: int,
    used_redirector: bool,
    is_shortener: bool,
    domain_changed: bool,
) -> list[str]:
    if redirect_count <= 0 or not domain_changed:
        return []

    reasons: list[str] = []
    if used_redirector or is_shortener:
        reasons.append("redirector_origin")

    hop_registrable_domains = {
        registrable_domain(str(item.get("domain") or "").strip().lower())
        for item in redirect_chain
        if item.get("domain")
    }
    final_registrable = registrable_domain(final_domain)
    if final_registrable:
        hop_registrable_domains.add(final_registrable)
    hop_registrable_domains.discard(None)
    if len(hop_registrable_domains) >= 3:
        reasons.append("multi_domain_chain")

    if _is_ip_literal_host(final_domain):
        reasons.append("ip_literal_final_host")
    if _has_punycode_label(final_domain):
        reasons.append("punycode_final_host")
    if _has_suspicious_tld(final_domain):
        reasons.append("suspicious_tld")
    if _has_unusual_host_shape(final_domain):
        reasons.append("unusual_final_host_shape")
    if _has_credential_url_signals(final_url):
        reasons.append("credential_url_signals")

    if _is_benign_share_destination(final_url, final_domain):
        return []

    return reasons


def _build_opener(settings: Settings):
    https_handler = HTTPSHandler(
        context=ssl.create_default_context() if settings.url_resolution_verify_tls else ssl._create_unverified_context()
    )
    return build_opener(_NoRedirectHandler(), HTTPHandler(), https_handler)


def _fetch_url_step(url: str, settings: Settings) -> dict[str, Any]:
    opener = _build_opener(settings)
    request = Request(
        url,
        headers={
            "User-Agent": settings.url_resolution_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=settings.url_resolution_timeout_seconds) as response:
            return {
                "status_code": int(getattr(response, "status", response.getcode())),
                "location": response.headers.get("Location"),
            }
    except HTTPError as exc:
        return {
            "status_code": int(exc.code),
            "location": exc.headers.get("Location"),
        }
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(str(reason)) from exc


def analyze_url(
    value: str,
    *,
    settings: Settings | None = None,
    resolve_urls: bool | None = None,
    fetcher: UrlFetcher | None = None,
) -> dict[str, Any]:
    settings = settings or get_settings()
    normalized_url = _normalize_url(value)
    initial_domain = extract_url_domain(normalized_url)
    final_url = normalized_url or value
    final_domain = initial_domain
    resolution_status = "disabled"
    resolution_error: str | None = None
    redirect_chain: list[dict[str, Any]] = []

    enabled = settings.url_resolution_enabled if resolve_urls is None else resolve_urls
    used_redirector = is_known_redirector(initial_domain)
    is_shortener = is_shortener_domain(initial_domain)

    if not enabled:
        pass
    elif not normalized_url:
        resolution_status = "error"
        resolution_error = "URL is empty"
    else:
        parsed = urlsplit(normalized_url)
        if parsed.scheme.lower() not in {"http", "https"}:
            resolution_status = "unsupported_scheme"
            resolution_error = f"Unsupported scheme: {parsed.scheme or 'unknown'}"
        else:
            fetch = fetcher or (lambda current: _fetch_url_step(current, settings))
            current = normalized_url
            seen: set[str] = set()
            max_steps = max(1, settings.url_resolution_max_hops + 1)

            for index in range(1, max_steps + 1):
                if current in seen:
                    final_url = current
                    resolution_status = "loop_detected"
                    resolution_error = "Redirect loop detected"
                    break
                seen.add(current)

                current_domain = extract_url_domain(current)
                try:
                    step_result = fetch(current)
                except Exception as exc:  # pragma: no cover - exercised through tests via fetcher
                    final_url = current
                    final_domain = current_domain
                    resolution_status = "error"
                    resolution_error = str(exc)
                    redirect_chain.append(
                        {
                            "index": index,
                            "url": current,
                            "domain": current_domain,
                            "status_code": None,
                            "location": None,
                        }
                    )
                    break

                status_code = step_result.get("status_code")
                location = step_result.get("location")
                next_url = None
                if location and isinstance(status_code, int) and 300 <= status_code < 400:
                    next_url = _normalize_url(urljoin(current, str(location)))

                redirect_chain.append(
                    {
                        "index": index,
                        "url": current,
                        "domain": current_domain,
                        "status_code": status_code,
                        "location": next_url,
                    }
                )

                if not next_url:
                    final_url = current
                    final_domain = current_domain
                    resolution_status = "resolved" if index > 1 or any(item.get("location") for item in redirect_chain) else "no_redirect"
                    break

                final_url = next_url
                final_domain = extract_url_domain(next_url)
                if index == max_steps:
                    resolution_status = "max_hops_exceeded"
                    resolution_error = f"Redirect chain exceeded {settings.url_resolution_max_hops} hops"
                    break

                current = next_url

    domain_changed = bool(
        initial_domain
        and final_domain
        and registrable_domain(initial_domain) != registrable_domain(final_domain)
    )
    redirect_count = sum(1 for item in redirect_chain if item.get("location"))
    redirect_risk_reasons = _redirect_risk_reasons(
        final_url=final_url,
        initial_domain=initial_domain,
        final_domain=final_domain,
        redirect_chain=redirect_chain,
        redirect_count=redirect_count,
        used_redirector=used_redirector,
        is_shortener=is_shortener,
        domain_changed=domain_changed,
    )

    return {
        "original_url": value,
        "normalized_url": normalized_url or value,
        "initial_domain": initial_domain,
        "final_url": final_url,
        "final_domain": final_domain,
        "redirect_count": redirect_count,
        "is_shortener": is_shortener,
        "used_redirector": used_redirector,
        "domain_changed": domain_changed,
        "suspicious_redirect": bool(redirect_risk_reasons),
        "redirect_risk_score": len(redirect_risk_reasons),
        "redirect_risk_reasons": redirect_risk_reasons,
        "resolution_status": resolution_status,
        "resolution_error": resolution_error,
        "redirect_chain": redirect_chain,
    }


def build_url_analysis(
    urls: Sequence[str] | None,
    *,
    settings: Settings | None = None,
    resolve_urls: bool | None = None,
    fetcher: UrlFetcher | None = None,
) -> list[dict[str, Any]]:
    if not urls:
        return []

    seen: set[str] = set()
    ordered_urls: list[str] = []
    for item in urls:
        cleaned = _normalize_url(item)
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered_urls.append(cleaned)

    settings = settings or get_settings()
    max_urls = settings.url_resolution_max_urls
    if max_urls is not None and max_urls < 1:
        max_urls = None
    analyses: list[dict[str, Any]] = []
    for index, url in enumerate(ordered_urls):
        if max_urls is not None and index >= max_urls:
            domain = extract_url_domain(url)
            analyses.append(
                {
                    "original_url": url,
                    "normalized_url": url,
                    "initial_domain": domain,
                    "final_url": url,
                    "final_domain": domain,
                    "redirect_count": 0,
                    "is_shortener": is_shortener_domain(domain),
                    "used_redirector": is_known_redirector(domain),
                    "domain_changed": False,
                    "suspicious_redirect": False,
                    "redirect_risk_score": 0,
                    "redirect_risk_reasons": [],
                    "resolution_status": "skipped_limit",
                    "resolution_error": f"Skipped after {max_urls} URLs",
                    "redirect_chain": [],
                }
            )
            continue
        analyses.append(
            analyze_url(
                url,
                settings=settings,
                resolve_urls=resolve_urls,
                fetcher=fetcher,
            )
        )
    return analyses


def build_static_url_analysis(urls: Sequence[str] | None) -> list[dict[str, Any]]:
    return build_url_analysis(urls, resolve_urls=False)


def resolved_urls_for_scoring(urls: Sequence[str], url_analysis: Sequence[dict[str, Any]] | None) -> list[str]:
    seen: set[str] = set()
    resolved: list[str] = []
    original_set = {item.strip() for item in urls if item and item.strip()}

    for item in url_analysis or []:
        final_url = str(item.get("final_url") or "").strip()
        if not final_url or final_url in original_set or final_url in seen:
            continue
        seen.add(final_url)
        resolved.append(final_url)
    return resolved

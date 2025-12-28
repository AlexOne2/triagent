import hashlib
import re
from html.parser import HTMLParser
from typing import Iterable, List, Optional, Sequence


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.append(value)


URL_REGEX = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
SUSPICIOUS_TLDS = {"ru", "cn", "kp", "ir", "biz", "top", "xyz"}
URL_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd"}
URGENT_KEYWORDS = {
    "urgent",
    "action required",
    "verify",
    "password",
    "reset",
    "immediately",
    "suspended",
    "payment",
}


def normalize_subject(subject: Optional[str]) -> str:
    if not subject:
        return ""
    text = subject.strip().lower()
    text = re.sub(r"^\s*(re|fw|fwd)\s*:\s*", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


def normalize_text(text: Optional[str]) -> str:
    if not text:
        return ""
    cleaned = text.strip().lower()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def strip_html(html: Optional[str]) -> str:
    if not html:
        return ""
    text = re.sub(r"<script.*?>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style.*?>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_urls(body_text: Optional[str], body_html: Optional[str]) -> List[str]:
    urls = set()
    if body_text:
        for match in URL_REGEX.findall(body_text):
            urls.add(_clean_url(match))
    if body_html:
        parser = _LinkParser()
        parser.feed(body_html)
        for link in parser.links:
            if link.lower().startswith("http"):
                urls.add(_clean_url(link))
        for match in URL_REGEX.findall(body_html):
            urls.add(_clean_url(match))
    return sorted({url for url in urls if url})


def _clean_url(url: str) -> str:
    cleaned = url.strip().strip("'\"()[]{}.,;:")
    return cleaned


def body_snippet(body_text: Optional[str], body_html: Optional[str], length: int = 200) -> str:
    if body_text:
        return normalize_text(body_text)[:length]
    return normalize_text(strip_html(body_html))[:length]


def compute_fingerprint(
    subject: Optional[str],
    from_addr: Optional[str],
    body_text: Optional[str],
    body_html: Optional[str],
    urls: Sequence[str],
) -> str:
    norm_subject = normalize_subject(subject)
    from_part = (from_addr or "").strip().lower()
    snippet = body_snippet(body_text, body_html)
    sorted_urls = ",".join(sorted({url.lower() for url in urls}))
    fingerprint_source = f"{norm_subject}|{from_part}|{snippet}|{sorted_urls}"
    return hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()


def calculate_risk(
    subject: Optional[str],
    body_text: Optional[str],
    from_addr: Optional[str],
    mailbox_domain: Optional[str],
    urls: Sequence[str],
    from_display_name: Optional[str] = None,
) -> int:
    score = 0

    sender_domain = None
    if from_addr and "@" in from_addr:
        sender_domain = from_addr.split("@")[-1].lower()
    if sender_domain and mailbox_domain and sender_domain != mailbox_domain.lower():
        score += 20

    url_domains = {extract_domain(url) for url in urls}
    if any(domain and domain.split(".")[-1] in SUSPICIOUS_TLDS for domain in url_domains):
        score += 15

    if urls:
        score += min(len(urls) * 5, 30)

    if any(domain in URL_SHORTENERS for domain in url_domains):
        score += 15

    if from_display_name and from_addr:
        local_part = from_addr.split("@")[0].lower()
        display = from_display_name.lower()
        if local_part not in display and (sender_domain and sender_domain not in display):
            score += 10

    content = " ".join(filter(None, [subject, body_text])).lower()
    if any(keyword in content for keyword in URGENT_KEYWORDS):
        score += 10

    return min(score, 100)


def extract_domain(url: str) -> Optional[str]:
    match = re.search(r"https?://([^/]+)", url, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).lower()


def hash_reporter(email: Optional[str], salt: str) -> Optional[str]:
    if not email:
        return None
    payload = f"{salt}:{email.lower()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def unique_sorted(values: Iterable[str]) -> List[str]:
    return sorted({value for value in values if value})

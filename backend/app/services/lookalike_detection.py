from __future__ import annotations

from email.utils import parseaddr
from typing import Literal

from app.services.url_resolution import registrable_domain

LookalikeField = Literal["from_addr", "reply_to", "return_path"]
LookalikeMatchType = Literal["brand_affix", "deceptive_subdomain", "edit_distance", "homoglyph"]
LookalikeConfidence = Literal["high", "medium", "low"]

_CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
    }
)


def extract_email_domain(value: str | None) -> str | None:
    if not value:
        return None
    parsed_addr = parseaddr(value)[1] or value
    cleaned = parsed_addr.strip().lower().strip("<>")
    if "@" not in cleaned:
        return None
    domain = cleaned.rsplit("@", 1)[-1].strip().strip(".")
    return domain or None


def _split_labels(domain: str | None) -> list[str]:
    if not domain:
        return []
    return [item for item in domain.lower().split(".") if item]


def _base_label(domain: str | None) -> str | None:
    registrable = registrable_domain(domain)
    labels = _split_labels(registrable)
    if len(labels) < 2:
        return labels[0] if labels else None
    return labels[0]


def _normalized_brand(value: str | None) -> str:
    if not value:
        return ""
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insertion = current[j - 1] + 1
            deletion = previous[j] + 1
            substitution = previous[j - 1] + (0 if left_char == right_char else 1)
            current.append(min(insertion, deletion, substitution))
        previous = current
    return previous[-1]


def _deceptive_subdomain_match(target_domain: str, observed_domain: str) -> dict | None:
    target_labels = _split_labels(target_domain)
    observed_labels = _split_labels(observed_domain)
    observed_registrable = registrable_domain(observed_domain)
    target_registrable = registrable_domain(target_domain)

    if (
        len(observed_labels) > len(target_labels)
        and observed_labels[: len(target_labels)] == target_labels
        and observed_registrable
        and observed_registrable != target_registrable
    ):
        return {
            "match_type": "deceptive_subdomain",
            "confidence": "high",
            "distance": None,
            "reasons": [
                f"Observed domain starts with the trusted mailbox domain {target_domain} as a deceptive subdomain.",
                f"Registrable domain is actually {observed_registrable}, not {target_registrable}.",
            ],
        }
    return None


def _brand_affix_match(target_label: str, observed_label: str) -> dict | None:
    if not target_label or not observed_label or target_label == observed_label:
        return None

    if target_label in observed_label and len(observed_label) > len(target_label):
        return {
            "match_type": "brand_affix",
            "confidence": "medium",
            "distance": None,
            "reasons": [
                f"Observed registrable label {observed_label} embeds trusted brand label {target_label}.",
                "Extra affixes were added around the trusted brand label.",
            ],
        }
    return None


def _homoglyph_match(target_label: str, observed_label: str) -> dict | None:
    if not target_label or not observed_label or target_label == observed_label:
        return None

    translated = observed_label.translate(_CONFUSABLE_TRANSLATION)
    if translated == target_label and observed_label != target_label:
        return {
            "match_type": "homoglyph",
            "confidence": "high",
            "distance": None,
            "reasons": [
                f"Observed registrable label {observed_label} normalizes to trusted brand label {target_label}.",
                "The mismatch is consistent with digit or homoglyph substitution.",
            ],
        }
    return None


def _edit_distance_match(target_label: str, observed_label: str) -> dict | None:
    if not target_label or not observed_label or target_label == observed_label:
        return None

    distance = _levenshtein_distance(observed_label, target_label)
    if distance <= 1:
        return {
            "match_type": "edit_distance",
            "confidence": "high",
            "distance": distance,
            "reasons": [
                f"Observed registrable label {observed_label} is one edit away from trusted brand label {target_label}.",
            ],
        }
    if distance == 2 and len(target_label) >= 8:
        return {
            "match_type": "edit_distance",
            "confidence": "medium",
            "distance": distance,
            "reasons": [
                f"Observed registrable label {observed_label} is two edits away from trusted brand label {target_label}.",
            ],
        }
    return None


def _candidate_match(target_domain: str, observed_domain: str) -> dict | None:
    target_registrable = registrable_domain(target_domain)
    observed_registrable = registrable_domain(observed_domain)
    if not target_registrable or not observed_registrable:
        return None
    if observed_registrable == target_registrable:
        return None

    deceptive = _deceptive_subdomain_match(target_domain, observed_domain)
    if deceptive:
        return deceptive

    target_label = _normalized_brand(_base_label(target_registrable))
    observed_label = _normalized_brand(_base_label(observed_registrable))
    for detector in (_homoglyph_match, _edit_distance_match, _brand_affix_match):
        match = detector(target_label, observed_label)
        if match:
            return match
    return None


def _field_entries(
    *,
    from_addr: str | None,
    reply_to: list[str] | None,
    return_path: str | None,
) -> list[tuple[LookalikeField, str]]:
    items: list[tuple[LookalikeField, str]] = []
    if from_addr:
        items.append(("from_addr", from_addr))
    for item in reply_to or []:
        if item:
            items.append(("reply_to", item))
    if return_path:
        items.append(("return_path", return_path))
    return items


def build_lookalike_analysis(
    *,
    mailbox_domain: str | None,
    from_addr: str | None,
    reply_to: list[str] | None = None,
    return_path: str | None,
) -> dict | None:
    target_domain = (mailbox_domain or "").strip().lower().strip(".")
    target_registrable = registrable_domain(target_domain)
    if not target_domain or not target_registrable:
        return None

    matches: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for field, address in _field_entries(from_addr=from_addr, reply_to=reply_to, return_path=return_path):
        observed_domain = extract_email_domain(address)
        if not observed_domain:
            continue
        detected = _candidate_match(target_domain, observed_domain)
        if not detected:
            continue
        key = (field, address.strip().lower(), detected["match_type"])
        if key in seen:
            continue
        seen.add(key)
        matches.append(
            {
                "field": field,
                "address": address,
                "observed_domain": observed_domain,
                "observed_registrable_domain": registrable_domain(observed_domain),
                "target_domain": target_domain,
                "target_registrable_domain": target_registrable,
                "match_type": detected["match_type"],
                "confidence": detected["confidence"],
                "distance": detected["distance"],
                "reasons": detected["reasons"],
            }
        )

    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    matches.sort(key=lambda item: (confidence_rank.get(item["confidence"], 9), item["field"], item["observed_domain"]))

    if matches:
        summary = (
            f"Detected {len(matches)} sender-domain lookalike signal"
            f"{'' if len(matches) == 1 else 's'} against trusted domain {target_domain}."
        )
    else:
        summary = f"No suspicious sender-domain lookalikes detected against trusted domain {target_domain}."

    return {
        "target_domain": target_domain,
        "target_registrable_domain": target_registrable,
        "has_suspected_lookalikes": bool(matches),
        "matches": matches,
        "summary": summary,
    }

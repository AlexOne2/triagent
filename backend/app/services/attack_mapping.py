from __future__ import annotations

from dataclasses import dataclass, field


MATRIX_NAME = "MITRE ATT&CK Enterprise"

TECHNIQUE_CATALOG: dict[str, dict[str, object]] = {
    "T1189": {
        "name": "Drive-by Compromise",
        "tactics": ["Initial Access"],
        "reference_url": "https://attack.mitre.org/techniques/T1189/",
    },
    "T1566": {
        "name": "Phishing",
        "tactics": ["Initial Access"],
        "reference_url": "https://attack.mitre.org/techniques/T1566/",
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "reference_url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactics": ["Initial Access"],
        "reference_url": "https://attack.mitre.org/techniques/T1566/002/",
    },
    "T1566.003": {
        "name": "Phishing: Spearphishing via Service",
        "tactics": ["Initial Access"],
        "reference_url": "https://attack.mitre.org/techniques/T1566/003/",
    },
    "T1586.002": {
        "name": "Compromise Accounts: Email Accounts",
        "tactics": ["Resource Development"],
        "reference_url": "https://attack.mitre.org/techniques/T1586/002/",
    },
    "T1598": {
        "name": "Phishing for Information",
        "tactics": ["Reconnaissance"],
        "reference_url": "https://attack.mitre.org/techniques/T1598/",
    },
    "T1598.002": {
        "name": "Phishing for Information: Spearphishing Attachment",
        "tactics": ["Reconnaissance"],
        "reference_url": "https://attack.mitre.org/techniques/T1598/002/",
    },
    "T1598.003": {
        "name": "Phishing for Information: Spearphishing Link",
        "tactics": ["Reconnaissance"],
        "reference_url": "https://attack.mitre.org/techniques/T1598/003/",
    },
    "T1656": {
        "name": "Impersonation",
        "tactics": ["Defense Evasion"],
        "reference_url": "https://attack.mitre.org/techniques/T1656/",
    },
    "T1672": {
        "name": "Email Spoofing",
        "tactics": ["Defense Evasion"],
        "reference_url": "https://attack.mitre.org/techniques/T1672/",
    },
}

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
IMPERSONATION_CODES = {"IMPER", "GOV_IMPER", "3P_IMPER", "T3P_IMPER", "VIP_IMPER"}
CONTEXT_ONLY_CODES = {"WHALE", "SPEAR", "POLY", "VOLUME"}


@dataclass(frozen=True)
class AttackEvidenceRef:
    kind: str
    value: str


@dataclass
class AttackTechniqueMapping:
    technique_id: str
    technique_name: str
    tactics: list[str]
    reference_url: str
    confidence: str
    rationales: list[str] = field(default_factory=list)
    evidence: list[AttackEvidenceRef] = field(default_factory=list)


@dataclass
class AttackMappingResult:
    matrix: str = MATRIX_NAME
    techniques: list[AttackTechniqueMapping] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    context_codes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class AttackMappingInput:
    classification_code: str | None = None
    status: str | None = None
    from_addr: str | None = None
    reply_to: list[str] = field(default_factory=list)
    return_path: str | None = None
    urls: list[str] = field(default_factory=list)
    url_analysis: list[dict] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    auth_spf_result: str | None = None
    auth_dkim_result: str | None = None
    auth_dmarc_result: str | None = None


def _email_domain(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower().strip("<>")
    if "@" not in cleaned:
        return None
    return cleaned.rsplit("@", 1)[-1] or None


class _TechniqueAccumulator:
    def __init__(self) -> None:
        self._items: dict[str, AttackTechniqueMapping] = {}
        self._notes: list[str] = []
        self._context_codes: list[str] = []

    def add(
        self,
        technique_id: str,
        *,
        confidence: str,
        rationale: str,
        evidence: list[AttackEvidenceRef] | None = None,
    ) -> None:
        catalog_entry = TECHNIQUE_CATALOG[technique_id]
        existing = self._items.get(technique_id)
        if existing is None:
            existing = AttackTechniqueMapping(
                technique_id=technique_id,
                technique_name=str(catalog_entry["name"]),
                tactics=list(catalog_entry["tactics"]),
                reference_url=str(catalog_entry["reference_url"]),
                confidence=confidence,
                rationales=[],
                evidence=[],
            )
            self._items[technique_id] = existing
        elif CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[existing.confidence]:
            existing.confidence = confidence

        if rationale not in existing.rationales:
            existing.rationales.append(rationale)
        for item in evidence or []:
            if item not in existing.evidence:
                existing.evidence.append(item)

    def note(self, message: str) -> None:
        if message not in self._notes:
            self._notes.append(message)

    def context_code(self, code: str) -> None:
        if code not in self._context_codes:
            self._context_codes.append(code)

    def build(self) -> AttackMappingResult:
        techniques = list(self._items.values())
        tactics = sorted({tactic for item in techniques for tactic in item.tactics})
        return AttackMappingResult(
            techniques=techniques,
            tactics=tactics,
            context_codes=self._context_codes,
            notes=self._notes,
        )


def _has_link_behaviors(mapping_input: AttackMappingInput) -> bool:
    return bool(mapping_input.urls or any(item.get("final_url") or item.get("original_url") for item in mapping_input.url_analysis))


def _has_attachment_behaviors(mapping_input: AttackMappingInput) -> bool:
    return bool(mapping_input.attachment_names)


def _has_suspicious_redirect(mapping_input: AttackMappingInput) -> bool:
    return any(bool(item.get("suspicious_redirect")) for item in mapping_input.url_analysis)


def _spoofing_evidence(mapping_input: AttackMappingInput) -> list[AttackEvidenceRef]:
    evidence: list[AttackEvidenceRef] = []
    for key, value in (
        ("auth.spf", mapping_input.auth_spf_result),
        ("auth.dkim", mapping_input.auth_dkim_result),
        ("auth.dmarc", mapping_input.auth_dmarc_result),
    ):
        if value:
            evidence.append(AttackEvidenceRef(kind=key, value=value))

    from_domain = _email_domain(mapping_input.from_addr)
    return_path_domain = _email_domain(mapping_input.return_path)
    if from_domain and return_path_domain and from_domain != return_path_domain:
        evidence.append(AttackEvidenceRef(kind="domain_mismatch", value=f"{from_domain}!={return_path_domain}"))
    for reply_to in mapping_input.reply_to:
        reply_domain = _email_domain(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            evidence.append(AttackEvidenceRef(kind="reply_to_mismatch", value=f"{from_domain}!={reply_domain}"))
    return evidence


def _add_delivery_mapping(
    accumulator: _TechniqueAccumulator,
    mapping_input: AttackMappingInput,
    *,
    confidence: str,
) -> None:
    code = (mapping_input.classification_code or "").upper()
    if _has_link_behaviors(mapping_input):
        rationale = "Observed URLs support link-based phishing delivery."
        if code == "THREAD_HIJACK":
            rationale = "MITRE ATT&CK notes thread hijacking as a phishing pattern; observed URLs make link delivery the closest explicit technique."
        elif code == "WEBMAIL":
            rationale = "Observed URLs indicate the phishing message also used link delivery."
        elif code in {"SPOOF", *IMPERSONATION_CODES, "FIN_FRAUD"}:
            rationale = "Deceptive email content plus observed URLs support spearphishing link delivery."
        accumulator.add(
            "T1566.002",
            confidence=confidence,
            rationale=rationale,
            evidence=[
                AttackEvidenceRef(kind="classification_code", value=code or "UNCLASSIFIED"),
                AttackEvidenceRef(kind="url_count", value=str(len(mapping_input.urls or mapping_input.url_analysis))),
            ],
        )
    if _has_attachment_behaviors(mapping_input):
        rationale = "Observed attachments support attachment-based phishing delivery."
        if code == "THREAD_HIJACK":
            rationale = "MITRE ATT&CK notes thread hijacking as a phishing pattern; observed attachments make attachment delivery the closest explicit technique."
        accumulator.add(
            "T1566.001",
            confidence=confidence,
            rationale=rationale,
            evidence=[
                AttackEvidenceRef(kind="classification_code", value=code or "UNCLASSIFIED"),
                AttackEvidenceRef(kind="attachment_count", value=str(len(mapping_input.attachment_names))),
            ],
        )


def build_attack_mapping(mapping_input: AttackMappingInput) -> AttackMappingResult:
    accumulator = _TechniqueAccumulator()
    code = (mapping_input.classification_code or "").upper() or None
    is_malicious = (mapping_input.status or "").upper() == "PHISHING"
    has_links = _has_link_behaviors(mapping_input)
    has_attachments = _has_attachment_behaviors(mapping_input)
    suspicious_redirect = _has_suspicious_redirect(mapping_input)

    if not code and is_malicious:
        _add_delivery_mapping(accumulator, mapping_input, confidence="low")
        return accumulator.build()

    if not code:
        return accumulator.build()

    code_evidence = [AttackEvidenceRef(kind="classification_code", value=code)]

    if code == "CRED_HARV":
        if has_links:
            evidence = list(code_evidence)
            if suspicious_redirect:
                evidence.append(AttackEvidenceRef(kind="url_behavior", value="suspicious_redirect"))
            accumulator.add(
                "T1598.003",
                confidence="high",
                rationale="Credential-harvesting emails with links align to MITRE's reconnaissance-focused spearphishing link technique.",
                evidence=evidence,
            )
        elif has_attachments:
            accumulator.add(
                "T1598.002",
                confidence="medium",
                rationale="Credential-harvesting delivered through attachments aligns to MITRE's reconnaissance-focused spearphishing attachment technique.",
                evidence=code_evidence,
            )
        else:
            accumulator.add(
                "T1598",
                confidence="medium",
                rationale="Credential-harvesting reflects phishing for information even when the exact delivery sub-technique is not preserved.",
                evidence=code_evidence,
            )
    elif code in {"RECON", "REPLY_SOLICIT"}:
        rationale = "The classification describes phishing intended to elicit information rather than execute malware."
        if code == "REPLY_SOLICIT":
            rationale = "MITRE ATT&CK explicitly notes phishing for information can occur through direct email exchanges used to solicit information."
        accumulator.add("T1598", confidence="high" if code == "REPLY_SOLICIT" else "medium", rationale=rationale, evidence=code_evidence)
    elif code == "DRIVE_BY":
        accumulator.add(
            "T1189",
            confidence="high",
            rationale="The classification explicitly identifies a drive-by compromise scenario.",
            evidence=code_evidence,
        )
    elif code == "MAL_ATTACH":
        accumulator.add(
            "T1566.001",
            confidence="high",
            rationale="The classification explicitly identifies a malicious attachment delivered by email.",
            evidence=code_evidence,
        )
    elif code in {"MAL_URL", "MAL_WEBAPP"}:
        evidence = list(code_evidence)
        if suspicious_redirect:
            evidence.append(AttackEvidenceRef(kind="url_behavior", value="suspicious_redirect"))
        accumulator.add(
            "T1566.002",
            confidence="high" if code == "MAL_URL" else "medium",
            rationale="The classification indicates malicious content delivered through links or a malicious web application.",
            evidence=evidence,
        )
    elif code == "MALWARE":
        if has_attachments:
            accumulator.add(
                "T1566.001",
                confidence="medium",
                rationale="Generic malware delivered by email most directly aligns to spearphishing attachment when attachments are present.",
                evidence=code_evidence,
            )
        if has_links:
            accumulator.add(
                "T1566.002",
                confidence="medium",
                rationale="Generic malware delivered through email links most directly aligns to spearphishing link.",
                evidence=code_evidence,
            )
        if not has_links and not has_attachments:
            accumulator.add(
                "T1566",
                confidence="low",
                rationale="The report is classified as malware-related email activity, but the preserved artifacts do not retain whether links or attachments were used.",
                evidence=code_evidence,
            )
    elif code == "COMPRO_SEND":
        accumulator.add(
            "T1586.002",
            confidence="high",
            rationale="The classification indicates a compromised sender account, which aligns to MITRE's compromised email accounts technique.",
            evidence=code_evidence,
        )
        _add_delivery_mapping(accumulator, mapping_input, confidence="medium")
    elif code == "SPOOF":
        spoof_evidence = code_evidence + _spoofing_evidence(mapping_input)
        high_confidence = any(item.kind in {"domain_mismatch", "reply_to_mismatch"} for item in spoof_evidence) or any(
            item.value in {"fail", "softfail", "permerror"} for item in spoof_evidence if item.kind.startswith("auth.")
        )
        accumulator.add(
            "T1672",
            confidence="high" if high_confidence else "medium",
            rationale="The classification indicates sender spoofing, which MITRE ATT&CK models explicitly as Email Spoofing.",
            evidence=spoof_evidence,
        )
        _add_delivery_mapping(accumulator, mapping_input, confidence="medium")
    elif code == "WEBMAIL":
        accumulator.add(
            "T1566.003",
            confidence="medium",
            rationale="MITRE ATT&CK defines spearphishing via service to include personal webmail and other non-enterprise-controlled services.",
            evidence=code_evidence,
        )
        _add_delivery_mapping(accumulator, mapping_input, confidence="medium")
    elif code in IMPERSONATION_CODES:
        accumulator.add(
            "T1656",
            confidence="high",
            rationale="The classification indicates impersonation of a trusted sender or organization.",
            evidence=code_evidence,
        )
        _add_delivery_mapping(accumulator, mapping_input, confidence="medium")
    elif code == "THREAD_HIJACK":
        if has_links or has_attachments:
            _add_delivery_mapping(accumulator, mapping_input, confidence="medium")
        else:
            accumulator.add(
                "T1566",
                confidence="medium",
                rationale="MITRE ATT&CK's phishing technique explicitly cites thread hijacking when adversaries add victims to existing email threads with malicious content.",
                evidence=code_evidence,
            )
    elif code == "FIN_FRAUD":
        accumulator.context_code(code)
        accumulator.note(
            "FIN_FRAUD describes the fraud objective. ATT&CK techniques are asserted only when supporting delivery or deception evidence is also present."
        )
        _add_delivery_mapping(accumulator, mapping_input, confidence="low" if is_malicious else "medium")
    elif code in CONTEXT_ONLY_CODES:
        accumulator.context_code(code)
        accumulator.note(
            f"{code} describes campaign scope or targeting context rather than a standalone ATT&CK technique."
        )
        if is_malicious:
            _add_delivery_mapping(accumulator, mapping_input, confidence="low")
    else:
        accumulator.context_code(code)
        accumulator.note(f"{code} does not currently have an explicit ATT&CK rule and is preserved as analyst context.")
        if is_malicious:
            _add_delivery_mapping(accumulator, mapping_input, confidence="low")

    return accumulator.build()

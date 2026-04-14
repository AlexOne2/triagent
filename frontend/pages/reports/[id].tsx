import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  AttackTechniqueMapping,
  Attachment,
  AuthStatus,
  FlaggedArtifact,
  Report,
  ReportResolutionEvent,
  UrlAnalysis,
  UrlResolutionStatus,
  deleteReport,
  downloadReportAttachment,
  downloadReportEvidenceJson,
  downloadReportEvidenceMarkdown,
  downloadReportEvidencePdf,
  downloadReportIocsCsv,
  downloadReportIocsJson,
  downloadReportOriginalMessage,
  fetchReport,
  fetchReportAttachments,
  fetchReportResolutions,
  reopenReport,
} from "../../lib/api";
import ResolveDrawer from "../../components/ResolveDrawer";
import { useAuth } from "../../lib/auth-context";
import { artifactKey, buildReportArtifacts, domainFromUrl } from "../../lib/report-artifacts";

function authStatusLabel(status?: AuthStatus | null): string {
  if (!status || status === "unknown") return "Unknown";
  if (status === "softfail") return "Softfail";
  if (status === "temperror") return "Temp error";
  if (status === "permerror") return "Perm error";
  return status.charAt(0).toUpperCase() + status.slice(1);
}

function authStatusClass(status?: AuthStatus | null): string {
  const normalized = status || "unknown";
  return `auth-status auth-status-${normalized}`;
}

function authStatusTone(status?: AuthStatus | null): "good" | "bad" | "neutral" {
  if (status === "pass") return "good";
  if (status && status !== "unknown" && status !== "none") return "bad";
  return "neutral";
}

function hasValue(value?: string | null): boolean {
  return !!value && value.trim().length > 0;
}

function hasAnyValue(values: Array<string | null | undefined>): boolean {
  return values.some((value) => hasValue(value));
}

function displayAuthValue(value?: string | null, fallback = "unknown"): string {
  return hasValue(value) ? value!.trim() : fallback;
}

function extractRecord(rawValue: string | null | undefined, prefix: "spf" | "dmarc"): string | null {
  if (!hasValue(rawValue)) return null;
  const source = rawValue!.trim();
  const pattern =
    prefix === "spf" ? /(v=spf1\b.*)$/i : /(v=dmarc1\b.*)$/i;
  const match = source.match(pattern);
  return match ? match[1].trim() : null;
}

function extractParenthesized(rawValue: string | null | undefined): string | null {
  if (!hasValue(rawValue)) return null;
  const match = rawValue!.match(/\(([^()]*)\)/);
  return match ? match[1].trim() : null;
}

function formatSpfOriginatingIp(ip?: string | null, sourceHeader?: string | null): string {
  const cleanIp = hasValue(ip) ? ip!.trim() : null;
  const cleanSource = hasValue(sourceHeader) ? sourceHeader!.trim() : null;
  if (cleanIp && cleanSource) return `${cleanIp} (${cleanSource})`;
  if (cleanIp) return cleanIp;
  return "unknown";
}

function formatDkimVerificationSummary(signatureCount: number, statuses: AuthStatus[]): string {
  if (!signatureCount) return "No signatures";
  const counts = statuses.reduce<Record<string, number>>((acc, status) => {
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, {});
  const summary = Object.entries(counts)
    .map(([status, count]) => `${count} ${authStatusLabel(status as AuthStatus).toUpperCase()}`)
    .join(", ");
  return `${signatureCount} signature${signatureCount === 1 ? "" : "s"} - ${summary}`;
}

function formatSelectorDisplay(selector?: string | null, signingDomain?: string | null): string {
  if (hasValue(selector) && hasValue(signingDomain)) {
    return `${selector!.trim()}._domainkey.${signingDomain!.trim()}`;
  }
  return displayAuthValue(selector);
}

function formatDmarcRecord(policy?: string | null, raw?: string | null): string {
  const parsed = extractRecord(raw, "dmarc");
  if (parsed) return parsed;
  if (hasValue(policy)) {
    const cleaned = policy!.trim().toLowerCase();
    return cleaned.toLowerCase().startsWith("v=dmarc1") ? cleaned : `v=DMARC1; p=${cleaned};`;
  }
  return "unknown";
}

function displayFieldValue(value?: string | null, fallback = "-"): string {
  return hasValue(value) ? value!.trim() : fallback;
}

function stripAngleBrackets(value?: string | null): string | null {
  if (!hasValue(value)) return null;
  return value!.trim().replace(/^<|>$/g, "");
}

function formatAttachmentSize(sizeBytes?: number | null): string {
  if (sizeBytes == null || Number.isNaN(sizeBytes)) return "unknown";
  if (sizeBytes < 1024) return `${sizeBytes} B`;
  const kb = sizeBytes / 1024;
  if (kb < 1024) return `${kb.toFixed(2)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(2)} MB`;
}

function attachmentTypeLabel(attachment: Attachment): string {
  const filename = attachment.filename?.toLowerCase() || "";
  if (filename.endsWith(".pkpass") || filename.endsWith(".zip")) return "ZIP";
  if (filename.endsWith(".ics")) return "ICS";
  if (filename.endsWith(".pdf")) return "PDF";
  if (filename.endsWith(".docx")) return "DOCX";
  if (filename.endsWith(".xlsx")) return "XLSX";
  if (filename.endsWith(".pptx")) return "PPTX";

  const contentType = attachment.content_type?.toLowerCase() || "";
  if (contentType === "text/calendar") return "ICS";
  if (contentType.includes("zip")) return "ZIP";
  if (contentType === "application/pdf") return "PDF";

  const extension = attachment.filename?.split(".").pop()?.trim();
  if (extension) return extension.toUpperCase();
  return attachment.content_type || "unknown";
}

function originalMessageTypeLabel(report: Report): string {
  const filename = report.original_filename?.toLowerCase() || "";
  if (filename.endsWith(".eml")) return "EML";
  if (filename.endsWith(".msg")) return "MSG";

  const contentType = report.original_content_type?.toLowerCase() || "";
  if (contentType === "message/rfc822") return "EML";
  if (contentType === "application/vnd.ms-outlook") return "MSG";

  const extension = report.original_filename?.split(".").pop()?.trim();
  if (extension) return extension.toUpperCase();
  return report.original_content_type || "unknown";
}

type TransmissionHop = {
  index: number;
  raw: string;
  timestamp?: string | null;
  receivedFrom?: string | null;
  receivedBy?: string | null;
  protocol?: string | null;
};

type HeaderEntry = {
  key: string;
  value: string;
};

type UrlRecord = {
  originalUrl: string;
  initialDomain: string | null;
  finalUrl: string | null;
  finalDomain: string | null;
  redirectCount: number;
  isShortener: boolean;
  domainChanged: boolean;
  suspiciousRedirect: boolean;
  resolutionStatus: UrlResolutionStatus;
  resolutionError?: string | null;
  redirectChain: UrlAnalysis["redirect_chain"];
  originalUrlArtifact?: FlaggedArtifact;
  initialDomainArtifact?: FlaggedArtifact;
  finalUrlArtifact?: FlaggedArtifact;
  finalDomainArtifact?: FlaggedArtifact;
};

function urlResolutionLabel(status?: UrlResolutionStatus | null): string {
  switch (status) {
    case "resolved":
      return "Resolved";
    case "no_redirect":
      return "No redirect";
    case "max_hops_exceeded":
      return "Max hops";
    case "loop_detected":
      return "Loop detected";
    case "unsupported_scheme":
      return "Unsupported";
    case "skipped_limit":
      return "Skipped";
    case "error":
      return "Error";
    case "disabled":
    default:
      return "Not resolved";
  }
}

function urlResolutionTone(status?: UrlResolutionStatus | null): "good" | "warn" | "bad" | "neutral" {
  if (status === "resolved" || status === "no_redirect") return "good";
  if (status === "max_hops_exceeded" || status === "loop_detected") return "warn";
  if (status === "error") return "bad";
  return "neutral";
}

function attackConfidenceLabel(confidence?: string | null): string {
  if (!confidence) return "Unknown";
  return confidence.charAt(0).toUpperCase() + confidence.slice(1);
}

function attackConfidenceClass(confidence?: string | null): string {
  const normalized = (confidence || "unknown").toLowerCase();
  return `attack-confidence attack-confidence-${normalized}`;
}

function formatAttackEvidenceKind(kind: string): string {
  return kind
    .split(/[._]/)
    .filter(Boolean)
    .map((part) => {
      if (part === "spf" || part === "dkim" || part === "dmarc" || part === "url") return part.toUpperCase();
      return part.charAt(0).toUpperCase() + part.slice(1);
    })
    .join(" ");
}

type AttackTechniqueCardProps = {
  technique: AttackTechniqueMapping;
};

function AttackTechniqueCard({ technique }: AttackTechniqueCardProps) {
  return (
    <section className="attack-technique-card">
      <div className="attack-technique-header">
        <div>
          <a href={technique.reference_url} target="_blank" rel="noreferrer" className="attack-technique-link">
            {technique.technique_id}
          </a>
          <h3>{technique.technique_name}</h3>
        </div>
        <span className={attackConfidenceClass(technique.confidence)}>{attackConfidenceLabel(technique.confidence)}</span>
      </div>
      <div className="attack-pill-list">
        {technique.tactics.map((tactic) => (
          <span key={tactic} className="attack-pill">
            {tactic}
          </span>
        ))}
      </div>
      {technique.rationales.length > 0 ? (
        <div className="attack-technique-block">
          <h4>Why this maps</h4>
          <ul className="attack-list">
            {technique.rationales.map((rationale, index) => (
              <li key={`${technique.technique_id}-rationale-${index}`}>{rationale}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {technique.evidence.length > 0 ? (
        <div className="attack-technique-block">
          <h4>Evidence used</h4>
          <ul className="attack-list attack-evidence-list">
            {technique.evidence.map((item, index) => (
              <li key={`${technique.technique_id}-evidence-${item.kind}-${item.value}-${index}`}>
                <span>{formatAttackEvidenceKind(item.kind)}</span>
                <code>{item.value}</code>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function normalizeHeaderValues(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).filter(Boolean);
  }
  if (typeof value === "string" && value.trim()) {
    return [value];
  }
  return [];
}

function flattenHeaderEntries(headers: Record<string, unknown>, predicate: (key: string) => boolean): HeaderEntry[] {
  const entries: HeaderEntry[] = [];

  for (const [key, value] of Object.entries(headers)) {
    if (!predicate(key)) continue;
    const values = normalizeHeaderValues(value);
    if (values.length === 0) continue;
    values.forEach((item) => {
      entries.push({ key, value: item });
    });
  }

  return entries;
}

function matchSection(raw: string, pattern: RegExp): string | null {
  const match = raw.match(pattern);
  return match ? match[1].trim() : null;
}

function parseReceivedHeader(raw: string, index: number): TransmissionHop {
  const trimmed = raw.trim();
  const lastSemicolon = trimmed.lastIndexOf(";");
  const main = lastSemicolon >= 0 ? trimmed.slice(0, lastSemicolon).trim() : trimmed;
  const timestamp = lastSemicolon >= 0 ? trimmed.slice(lastSemicolon + 1).trim() : null;
  const receivedFrom = matchSection(main, /\bfrom\s+(.+?)(?=\s+\bby\b|$)/i);
  const receivedBy = matchSection(main, /\bby\s+(.+?)(?=\s+\bwith\b|\s+\bid\b|\s+\bfor\b|$)/i);
  const protocol = matchSection(main, /\bwith\s+(.+?)(?=\s+\bid\b|\s+\bfor\b|$)/i);

  return {
    index,
    raw: trimmed,
    timestamp,
    receivedFrom,
    receivedBy,
    protocol,
  };
}

export default function ReportDetailPage() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("reports.read");
  const canResolve = hasPermission("reports.resolve");
  const canReopen = hasPermission("reports.reopen");
  const canDelete = hasPermission("reports.admin_override");
  const router = useRouter();
  const { id } = router.query;
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [attachmentsLoading, setAttachmentsLoading] = useState(false);
  const [attachmentsError, setAttachmentsError] = useState<string | null>(null);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [downloadingAttachmentId, setDownloadingAttachmentId] = useState<number | null>(null);
  const [downloadingOriginalMessage, setDownloadingOriginalMessage] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [exportingFormat, setExportingFormat] = useState<"md" | "pdf" | "json" | "iocs_json" | "iocs_csv" | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [stagedArtifactKeys, setStagedArtifactKeys] = useState<string[]>([]);
  const [xHeaderQuery, setXHeaderQuery] = useState("");
  const [actionsMenuOpen, setActionsMenuOpen] = useState(false);
  const [downloadMenuOpen, setDownloadMenuOpen] = useState(false);
  const [auditLogOpen, setAuditLogOpen] = useState(false);
  const [attachmentMenuId, setAttachmentMenuId] = useState<number | null>(null);
  const [attachmentFlagMenuId, setAttachmentFlagMenuId] = useState<number | null>(null);
  const [resolutionEvents, setResolutionEvents] = useState<ReportResolutionEvent[]>([]);
  const [resolutionsLoading, setResolutionsLoading] = useState(false);
  const [resolutionsError, setResolutionsError] = useState<string | null>(null);
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const actionsMenuRef = useRef<HTMLDivElement | null>(null);
  const attachmentMenuRef = useRef<HTMLDivElement | null>(null);
  const copyResetTimerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    if (!id) return;
    let active = true;
    setLoading(true);
    fetchReport(id as string)
      .then((data) => {
        if (!active) return;
        setReport(data);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || "Failed to load report");
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [id, canRead]);

  useEffect(() => {
    if (!canRead || !report?.id) {
      setAttachments([]);
      setAttachmentsLoading(false);
      setAttachmentsError(null);
      return;
    }
    let active = true;
    setAttachmentsLoading(true);
    setAttachmentsError(null);
    fetchReportAttachments(report.id)
      .then((data) => {
        if (!active) return;
        setAttachments(data);
      })
      .catch((err) => {
        if (!active) return;
        setAttachmentsError(err.message || "Failed to load attachments");
      })
      .finally(() => {
        if (!active) return;
        setAttachmentsLoading(false);
      });

    return () => {
      active = false;
    };
  }, [canRead, report?.id]);

  const urls = useMemo(() => {
    if (!report) return [];
    return report.urls_json || [];
  }, [report]);

  const latestReport = report;
  const latestHeaders = (report?.headers_json as Record<string, unknown>) || {};
  const authSummary = report?.auth_summary;
  const attackMapping = report?.attack_mapping;
  const spfRecord = extractRecord(authSummary?.raw_headers.received_spf || authSummary?.spf.raw, "spf");
  const dkimStatuses = authSummary?.dkim.signatures.map((signature) => signature.result) || [];
  const primarySignature = authSummary?.dkim.signatures[0];
  const hasSpfDetails = hasAnyValue([
    authSummary?.spf.source_header,
    authSummary?.spf.authserv_id,
    authSummary?.spf.receiver,
    authSummary?.spf.smtp_mailfrom,
    authSummary?.spf.smtp_helo,
    authSummary?.spf.return_path_domain,
    authSummary?.spf.originating_ip,
    authSummary?.spf.originating_rdns,
  ]);
  const hasDmarcDetails = hasAnyValue([
    authSummary?.dmarc.header_from,
    authSummary?.dmarc.aligned_from_domain,
    authSummary?.dmarc.aligned_mailfrom_domain,
    authSummary?.dmarc.policy,
  ]);
  const hasArcDetails = hasAnyValue([
    authSummary?.arc.instance,
    authSummary?.arc.seal_result,
    authSummary?.arc.message_signature_result,
  ]);
  const receivedHeaders = normalizeHeaderValues(latestHeaders["Received"]);
  const transmissionHops = useMemo(
    () =>
      [...receivedHeaders]
        .reverse()
        .map((raw, index) => parseReceivedHeader(raw, index + 1)),
    [receivedHeaders],
  );
  const xHeaderEntries = useMemo(
    () => flattenHeaderEntries(latestHeaders, (key) => key.toLowerCase().startsWith("x-")),
    [latestHeaders],
  );
  const filteredXHeaderEntries = useMemo(() => {
    const query = xHeaderQuery.trim().toLowerCase();
    if (!query) return xHeaderEntries;
    return xHeaderEntries.filter(
      (entry) => entry.key.toLowerCase().includes(query) || entry.value.toLowerCase().includes(query),
    );
  }, [xHeaderEntries, xHeaderQuery]);
  const availableArtifacts = useMemo(() => {
    if (!report) return [];
    return buildReportArtifacts(report, attachments);
  }, [report, attachments]);

  const [leftTab, setLeftTab] = useState("Details");
  const [rightTab, setRightTab] = useState("Rendered");

  useEffect(() => {
    if (!report) {
      setStagedArtifactKeys([]);
      return;
    }
    setStagedArtifactKeys((report.flagged_artifacts_json || []).map((artifact) => artifactKey(artifact)));
  }, [report]);

  useEffect(() => {
    if (!actionsMenuOpen) {
      setDownloadMenuOpen(false);
      return;
    }

    const handlePointerDown = (event: MouseEvent) => {
      if (!actionsMenuRef.current?.contains(event.target as Node)) {
        setActionsMenuOpen(false);
        setDownloadMenuOpen(false);
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setActionsMenuOpen(false);
        setDownloadMenuOpen(false);
      }
    };

    window.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleEscape);
    return () => {
      window.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleEscape);
    };
  }, [actionsMenuOpen]);

  useEffect(() => {
    if (attachmentMenuId == null) {
      setAttachmentFlagMenuId(null);
      return;
    }

    const handlePointerDown = (event: MouseEvent) => {
      if (!attachmentMenuRef.current?.contains(event.target as Node)) {
        setAttachmentMenuId(null);
        setAttachmentFlagMenuId(null);
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setAttachmentMenuId(null);
        setAttachmentFlagMenuId(null);
      }
    };

    window.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleEscape);
    return () => {
      window.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleEscape);
    };
  }, [attachmentMenuId]);

  useEffect(() => {
    return () => {
      if (copyResetTimerRef.current != null) {
        window.clearTimeout(copyResetTimerRef.current);
      }
    };
  }, []);

  const findArtifact = (kind: FlaggedArtifact["kind"], value?: string | null) => {
    if (!hasValue(value)) return undefined;
    return availableArtifacts.find((artifact) => artifact.kind === kind && artifact.value === value!.trim());
  };

  const urlRecords = useMemo(
    (): UrlRecord[] => {
      const source =
        report?.url_analysis_json && report.url_analysis_json.length > 0
          ? report.url_analysis_json
          : urls.map(
              (url): UrlAnalysis => ({
                original_url: url,
                normalized_url: url,
                initial_domain: domainFromUrl(url),
                final_url: url,
                final_domain: domainFromUrl(url),
                redirect_count: 0,
                is_shortener: false,
                used_redirector: false,
                domain_changed: false,
                suspicious_redirect: false,
                resolution_status: "disabled",
                resolution_error: null,
                redirect_chain: [],
              }),
            );

      return source.map((entry) => {
        const originalUrl = entry.original_url;
        const initialDomain = entry.initial_domain || domainFromUrl(originalUrl);
        const finalUrl = entry.final_url || originalUrl;
        const finalDomain = entry.final_domain || domainFromUrl(finalUrl || "");
        return {
          originalUrl,
          initialDomain,
          finalUrl,
          finalDomain,
          redirectCount: entry.redirect_count || 0,
          isShortener: !!entry.is_shortener,
          domainChanged: !!entry.domain_changed,
          suspiciousRedirect: !!entry.suspicious_redirect,
          resolutionStatus: entry.resolution_status,
          resolutionError: entry.resolution_error,
          redirectChain: entry.redirect_chain || [],
          originalUrlArtifact: findArtifact("URL", originalUrl),
          initialDomainArtifact: initialDomain ? findArtifact("URL_DOMAIN", initialDomain) : undefined,
          finalUrlArtifact: finalUrl ? findArtifact("URL", finalUrl) : undefined,
          finalDomainArtifact: finalDomain ? findArtifact("URL_DOMAIN", finalDomain) : undefined,
        };
      });
    },
    [report, urls, availableArtifacts],
  );
  const uniqueUrlDomains = useMemo(
    () => new Set(urlRecords.map((record) => record.finalDomain || record.initialDomain).filter(Boolean)).size,
    [urlRecords],
  );
  const redirectedUrlCount = useMemo(
    () => urlRecords.filter((record) => record.redirectCount > 0 || record.domainChanged).length,
    [urlRecords],
  );

  const toggleArtifact = (artifact?: FlaggedArtifact) => {
    if (!artifact) return;
    const key = artifactKey(artifact);
    setStagedArtifactKeys((current) =>
      current.includes(key) ? current.filter((item) => item !== key) : [...current, key],
    );
  };

  const renderFlagButton = (artifact?: FlaggedArtifact) => {
    if (!artifact) return null;
    const active = stagedArtifactKeys.includes(artifactKey(artifact));
    return (
      <button
        type="button"
        className={`flag-toggle ${active ? "active" : ""}`}
        aria-label={active ? "Unflag field" : "Flag field"}
        title={active ? "Marked for flagging" : "Flag this field"}
        onClick={() => toggleArtifact(artifact)}
      >
        ⚑
      </button>
    );
  };

  const handleCopyValue = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedValue(value);
      if (copyResetTimerRef.current != null) {
        window.clearTimeout(copyResetTimerRef.current);
      }
      copyResetTimerRef.current = window.setTimeout(() => setCopiedValue(null), 1600);
    } catch {
      setError("Failed to copy to clipboard.");
    }
  };

  const renderCopyButton = (value?: string | null) => {
    if (!hasValue(value)) return null;
    const cleanValue = value!.trim();
    const copied = copiedValue === cleanValue;
    return (
      <button
        type="button"
        className={`copy-inline-button ${copied ? "copied" : ""}`}
        onClick={() => void handleCopyValue(cleanValue)}
        aria-label={copied ? "Copied to clipboard" : "Copy to clipboard"}
        title={copied ? "Copied" : "Copy to clipboard"}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    );
  };

  const renderFieldRow = (label: string, value: ReactNode, artifact?: FlaggedArtifact) => (
    <>
      <label>{label}</label>
      <div className="detail-field-value">
        <span>{value}</span>
        {renderFlagButton(artifact)}
      </div>
    </>
  );

  const handleReopen = async () => {
    if (!report) return;
    setUpdating(true);
    try {
      const updated = await reopenReport(report.id);
      setReport(updated);
      setStagedArtifactKeys((updated.flagged_artifacts_json || []).map((artifact) => artifactKey(artifact)));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reopen report.");
    } finally {
      setUpdating(false);
    }
  };

  const handleEvidenceExport = async (format: "md" | "pdf" | "json" | "iocs_json" | "iocs_csv") => {
    if (!report || exportingFormat) return;
    setExportingFormat(format);
    setExportError(null);
    try {
      let download;
      if (format === "md") {
        download = await downloadReportEvidenceMarkdown(report.id);
      } else if (format === "pdf") {
        download = await downloadReportEvidencePdf(report.id);
      } else if (format === "json") {
        download = await downloadReportEvidenceJson(report.id);
      } else if (format === "iocs_json") {
        download = await downloadReportIocsJson(report.id);
      } else {
        download = await downloadReportIocsCsv(report.id);
      }
      const url = window.URL.createObjectURL(download.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download =
        download.filename ||
        (format === "iocs_json"
          ? `report-${report.id}-iocs.json`
          : format === "iocs_csv"
            ? `report-${report.id}-iocs.csv`
            : `report-${report.id}-evidence.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Failed to export evidence.");
    } finally {
      setExportingFormat(null);
    }
  };

  const handleOpenAuditLog = async () => {
    setAuditLogOpen((current) => !current);
    if (!report || resolutionEvents.length > 0 || resolutionsLoading) return;
    setResolutionsLoading(true);
    setResolutionsError(null);
    try {
      const events = await fetchReportResolutions(report.id);
      setResolutionEvents(events);
    } catch (err) {
      setResolutionsError(err instanceof Error ? err.message : "Failed to load audit log.");
    } finally {
      setResolutionsLoading(false);
    }
  };

  const handleDeleteReport = async () => {
    if (!report || deleting) return;
    const confirmed = window.confirm(
      `Delete report #${report.id}? This will remove the original upload, its attachments, and resolution history.`,
    );
    if (!confirmed) return;

    setDeleting(true);
    setError(null);
    setActionsMenuOpen(false);
    setDownloadMenuOpen(false);
    setAuditLogOpen(false);
    try {
      await deleteReport(report.id);
      await router.replace("/reports");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete report.");
      setDeleting(false);
    }
  };

  const handleDownloadAttachment = async (attachment: Attachment) => {
    if (!report || downloadingAttachmentId === attachment.id) return;
    setDownloadingAttachmentId(attachment.id);
    setError(null);
    setAttachmentMenuId(null);
    setAttachmentFlagMenuId(null);
    try {
      const download = await downloadReportAttachment(report.id, attachment.id, attachment.filename);
      const url = window.URL.createObjectURL(download.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = download.filename || attachment.filename || "attachment.bin";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download attachment.");
    } finally {
      setDownloadingAttachmentId(null);
    }
  };

  const handleDownloadOriginalMessage = async () => {
    if (!report || !report.has_original_message || downloadingOriginalMessage) return;
    setDownloadingOriginalMessage(true);
    setError(null);
    setActionsMenuOpen(false);
    setDownloadMenuOpen(false);
    try {
      const download = await downloadReportOriginalMessage(report.id, report.original_filename);
      const url = window.URL.createObjectURL(download.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = download.filename || report.original_filename || "original-message.bin";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download original message.");
    } finally {
      setDownloadingOriginalMessage(false);
    }
  };

  if (loading) {
    return (
      <main>
        <p>Loading...</p>
      </main>
    );
  }

  if (!canRead) {
    return (
      <main className="full">
        <h1>Report</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  if (error || !report) {
    return (
      <main>
        <p>{error || "Report not found"}</p>
        <Link href="/reports">Back to uploads</Link>
      </main>
    );
  }

  return (
    <main className="full report-detail-page">
      <header className="report-detail-header">
        <div>
          <div className="report-breadcrumb">
            <Link href="/reports">Uploads</Link>
            <span aria-hidden="true">›</span>
            <span>{report.subject || "(no subject)"}</span>
          </div>
          <h1>{report.subject || "(no subject)"}</h1>
        </div>
        <div className="report-detail-actions">
          {report.status === "OPEN" && canResolve ? (
            <button className="resolve-button" type="button" onClick={() => setDrawerOpen(true)} disabled={updating || deleting}>
              Resolve
            </button>
          ) : null}
          {report.status !== "OPEN" ? (
            <span className={report.status === "PHISHING" ? "badge phishing" : "badge"}>{report.status}</span>
          ) : null}
          {report.status !== "OPEN" && canReopen ? (
            <button className="resolve-button secondary" type="button" onClick={handleReopen} disabled={updating || deleting}>
              {updating ? "Reopening..." : "Reopen"}
            </button>
          ) : null}
          <div className="report-actions-menu" ref={actionsMenuRef}>
            <button
              className="kebab-button"
              type="button"
              aria-label="Open report actions"
              aria-expanded={actionsMenuOpen}
              onClick={() => setActionsMenuOpen((current) => !current)}
            >
              •••
            </button>
            {actionsMenuOpen ? (
              <div className="report-actions-dropdown" role="menu">
                <button className="report-action-item" type="button" onClick={() => void handleOpenAuditLog()}>
                  Audit log
                </button>
                <div
                  className="report-action-submenu"
                  onMouseEnter={() => setDownloadMenuOpen(true)}
                  onMouseLeave={() => setDownloadMenuOpen(false)}
                >
                  <button
                    className="report-action-item submenu-trigger"
                    type="button"
                    onClick={() => setDownloadMenuOpen((current) => !current)}
                  >
                    Download
                    <span aria-hidden="true">▸</span>
                  </button>
                  {downloadMenuOpen ? (
                    <div className="report-action-submenu-popout" role="menu">
                      <button
                        className="report-action-item"
                        type="button"
                        onClick={() => void handleDownloadOriginalMessage()}
                        disabled={!report.has_original_message || downloadingOriginalMessage || deleting}
                      >
                        {downloadingOriginalMessage ? "Downloading original..." : "Original sample"}
                      </button>
                      <button
                        className="report-action-item"
                        type="button"
                        onClick={() => void handleEvidenceExport("json")}
                        disabled={!!exportingFormat || deleting}
                      >
                        {exportingFormat === "json" ? "Exporting JSON..." : "JSON bundle"}
                      </button>
                      <button
                        className="report-action-item"
                        type="button"
                        onClick={() => void handleEvidenceExport("pdf")}
                        disabled={!!exportingFormat || deleting}
                      >
                        {exportingFormat === "pdf" ? "Exporting PDF..." : "PDF"}
                      </button>
                      <button
                        className="report-action-item"
                        type="button"
                        onClick={() => void handleEvidenceExport("md")}
                        disabled={!!exportingFormat || deleting}
                      >
                        {exportingFormat === "md" ? "Exporting Markdown..." : "Markdown"}
                      </button>
                      <button
                        className="report-action-item"
                        type="button"
                        onClick={() => void handleEvidenceExport("iocs_json")}
                        disabled={!!exportingFormat || deleting}
                      >
                        {exportingFormat === "iocs_json" ? "Exporting IOC JSON..." : "IOC JSON"}
                      </button>
                      <button
                        className="report-action-item"
                        type="button"
                        onClick={() => void handleEvidenceExport("iocs_csv")}
                        disabled={!!exportingFormat || deleting}
                      >
                        {exportingFormat === "iocs_csv" ? "Exporting IOC CSV..." : "IOC CSV"}
                      </button>
                    </div>
                  ) : null}
                </div>
                <button
                  className={`report-action-item ${canDelete ? "destructive" : "disabled"}`}
                  type="button"
                  disabled={!canDelete || deleting}
                  onClick={() => void handleDeleteReport()}
                >
                  {deleting ? "Deleting..." : "Delete"}
                </button>
              </div>
            ) : null}
            {auditLogOpen ? (
              <div className="report-audit-popover">
                <div className="report-audit-header">
                  <strong>Audit log</strong>
                  <button type="button" className="report-audit-close" onClick={() => setAuditLogOpen(false)}>
                    ×
                  </button>
                </div>
                {resolutionsLoading ? <p className="report-audit-empty">Loading…</p> : null}
                {resolutionsError ? <p className="report-audit-empty">{resolutionsError}</p> : null}
                {!resolutionsLoading && !resolutionsError && resolutionEvents.length === 0 ? (
                  <p className="report-audit-empty">No audit events yet.</p>
                ) : null}
                {!resolutionsLoading && !resolutionsError && resolutionEvents.length > 0 ? (
                  <ul className="report-audit-list">
                    {resolutionEvents.map((event) => (
                      <li key={event.id}>
                        <div>
                          <strong>{event.action}</strong>
                          <span>{new Date(event.created_at).toLocaleString()}</span>
                        </div>
                        <div>{event.actor}</div>
                        <div>
                          {event.disposition || event.status_after}
                          {event.classification_code ? ` · ${event.classification_code}` : ""}
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>
      </header>
      {exportError ? <p className="report-detail-error">{exportError}</p> : null}

      <section className="split report-detail-split">
        <div className="panel report-detail-panel">
          <div className="tabs report-detail-tabs">
            {["Details", "Authentication", "ATT&CK", "URLs", "Attachments", "Transmission", "X-Headers"].map((tab) => (
              <button
                key={tab}
                className={`tab ${leftTab === tab ? "active" : ""}`}
                onClick={() => setLeftTab(tab)}
                type="button"
              >
                {tab}
              </button>
            ))}
          </div>

          {leftTab === "Details" ? (
            <div className="kv detail-kv">
              {renderFieldRow("From", displayFieldValue(latestReport?.from_addr), findArtifact("FROM_ADDR", latestReport?.from_addr))}
              {renderFieldRow("Display Name", displayFieldValue(latestReport?.from_display_name))}
              {renderFieldRow("Sender", displayFieldValue(latestReport?.sender))}
              {renderFieldRow("To", latestReport?.to_addrs?.join(", ") || "-")}
              {renderFieldRow("Cc", latestReport?.cc_addrs?.join(", ") || "-")}
              {renderFieldRow("In-Reply-To", displayFieldValue(latestReport?.in_reply_to))}
              {renderFieldRow(
                "Timestamp",
                latestReport?.received_at
                  ? new Date(latestReport.received_at).toLocaleString()
                  : latestReport?.date
                  ? new Date(latestReport.date).toLocaleString()
                  : "-",
              )}
              {renderFieldRow("Reply-To", latestReport?.reply_to?.join(", ") || "-")}
              {renderFieldRow("Message ID", displayFieldValue(latestReport?.message_id))}
              {renderFieldRow(
                "Return-Path",
                displayFieldValue(stripAngleBrackets(latestReport?.return_path)),
                findArtifact("RETURN_PATH", latestReport?.return_path),
              )}
              {renderFieldRow(
                "Originating IP + rDNS",
                <>
                  {latestReport?.originating_ip || authSummary?.spf.originating_ip || "-"}
                  {latestReport?.originating_rdns || authSummary?.spf.originating_rdns
                    ? ` (${latestReport?.originating_rdns || authSummary?.spf.originating_rdns})`
                    : ""}
                </>,
                findArtifact("ORIGINATING_IP", latestReport?.originating_ip || authSummary?.spf.originating_ip),
              )}
            </div>
          ) : null}

          {leftTab === "Authentication" ? (
            <div className="detail-auth">
              <section className={`auth-section auth-section-${authStatusTone(authSummary?.spf.result)}`}>
                <div className="auth-section-header">
                  <h3>SPF</h3>
                  <span className={authStatusClass(authSummary?.spf.result)}>{authStatusLabel(authSummary?.spf.result)}</span>
                </div>
                <div className="kv auth-detail-grid">
                  {renderFieldRow(
                    "Originating IP",
                    formatSpfOriginatingIp(authSummary?.spf.originating_ip, authSummary?.spf.source_header),
                    findArtifact("ORIGINATING_IP", authSummary?.spf.originating_ip || latestReport?.originating_ip),
                  )}
                  {renderFieldRow("rDNS", displayAuthValue(authSummary?.spf.originating_rdns))}
                  {renderFieldRow(
                    "Return-Path domain",
                    displayAuthValue(authSummary?.spf.return_path_domain),
                    findArtifact("RETURN_PATH_DOMAIN", authSummary?.spf.return_path_domain),
                  )}
                  {renderFieldRow(
                    "SPF record",
                    authSummary?.spf.dns_record ||
                      spfRecord ||
                      extractParenthesized(authSummary?.raw_headers.received_spf || authSummary?.spf.raw) ||
                      "unknown",
                  )}
                  {!hasSpfDetails ? <div className="auth-empty">No structured SPF details parsed.</div> : null}
                </div>
              </section>

              <section className={`auth-section auth-section-${authStatusTone(authSummary?.dkim.result)}`}>
                <div className="auth-section-header">
                  <h3>DKIM</h3>
                  <span className={authStatusClass(authSummary?.dkim.result)}>{authStatusLabel(authSummary?.dkim.result)}</span>
                </div>
                <div className="auth-section-meta">
                  <span className="auth-meta-label">Verification(s)</span>
                  <span>{formatDkimVerificationSummary(authSummary?.dkim.signature_count || 0, dkimStatuses)}</span>
                </div>
                <div className="kv auth-detail-grid">
                  {renderFieldRow(
                    "Selector",
                    formatSelectorDisplay(primarySignature?.selector, primarySignature?.signing_domain),
                  )}
                  {renderFieldRow("Signing domain", displayAuthValue(primarySignature?.signing_domain))}
                  {renderFieldRow("Algorithm", displayAuthValue(primarySignature?.algorithm))}
                  {renderFieldRow("Verification", displayAuthValue(primarySignature?.result).toUpperCase())}
                </div>
                {authSummary?.dkim.signatures && authSummary.dkim.signatures.length > 1 ? (
                  <div className="auth-signature-list">
                    {authSummary.dkim.signatures.slice(1).map((signature, index) => (
                      <div key={`${signature.selector || "sig"}-${index + 1}`} className="auth-signature-item">
                        <div className="auth-signature-header">
                          <strong>Signature {index + 2}</strong>
                          <span className={authStatusClass(signature.result)}>{authStatusLabel(signature.result)}</span>
                        </div>
                        <div className="kv auth-detail-grid">
                          {renderFieldRow("Selector", formatSelectorDisplay(signature.selector, signature.signing_domain))}
                          {renderFieldRow("Signing domain", displayAuthValue(signature.signing_domain))}
                          {renderFieldRow("Algorithm", displayAuthValue(signature.algorithm))}
                          {renderFieldRow("Verification", displayAuthValue(signature.result).toUpperCase())}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </section>

              <section className={`auth-section auth-section-${authStatusTone(authSummary?.dmarc.result)}`}>
                <div className="auth-section-header">
                  <h3>DMARC</h3>
                  <span className={authStatusClass(authSummary?.dmarc.result)}>{authStatusLabel(authSummary?.dmarc.result)}</span>
                </div>
                <div className="kv auth-detail-grid">
                  {renderFieldRow(
                    "From domain",
                    displayAuthValue(authSummary?.dmarc.header_from),
                    findArtifact("FROM_DOMAIN", authSummary?.dmarc.header_from),
                  )}
                  {renderFieldRow(
                    "DMARC record",
                    authSummary?.dmarc.dns_record || formatDmarcRecord(authSummary?.dmarc.policy, authSummary?.dmarc.raw),
                  )}
                  {!hasDmarcDetails ? <div className="auth-empty">No structured DMARC details parsed.</div> : null}
                </div>
              </section>

              <section className={`auth-section auth-section-${authStatusTone(authSummary?.arc.result)}`}>
                <div className="auth-section-header">
                  <h3>ARC</h3>
                  <span className={authStatusClass(authSummary?.arc.result)}>{authStatusLabel(authSummary?.arc.result)}</span>
                </div>
                <div className="kv auth-detail-grid">
                  {hasValue(authSummary?.arc.instance)
                    ? renderFieldRow("Instance", authSummary!.arc.instance!)
                    : null}
                  {hasValue(authSummary?.arc.seal_result)
                    ? renderFieldRow("Seal result", authSummary!.arc.seal_result!)
                    : null}
                  {hasValue(authSummary?.arc.message_signature_result)
                    ? renderFieldRow("Message signature result", authSummary!.arc.message_signature_result!)
                    : null}
                  {!hasArcDetails ? <div className="auth-empty">No structured ARC details parsed.</div> : null}
                </div>
              </section>

              <details className="auth-raw-block">
                <summary>Raw authentication headers</summary>
                <div className="mono detail-mono auth-raw-mono">
                  {[
                    authSummary?.raw_headers.authentication_results
                      ? `Authentication-Results: ${authSummary.raw_headers.authentication_results}`
                      : null,
                    authSummary?.raw_headers.received_spf
                      ? `Received-SPF: ${authSummary.raw_headers.received_spf}`
                      : null,
                    authSummary?.raw_headers.arc_authentication_results
                      ? `ARC-Authentication-Results: ${authSummary.raw_headers.arc_authentication_results}`
                      : null,
                    authSummary?.raw_headers.arc_seal ? `ARC-Seal: ${authSummary.raw_headers.arc_seal}` : null,
                    authSummary?.raw_headers.arc_message_signature
                      ? `ARC-Message-Signature: ${authSummary.raw_headers.arc_message_signature}`
                      : null,
                  ]
                    .filter(Boolean)
                    .join("\n\n") || "No authentication headers found."}
                </div>
              </details>
            </div>
          ) : null}

          {leftTab === "ATT&CK" ? (
            <div className="detail-section attack-tab">
              <section className="attack-summary-card">
                <div className="attack-summary-header">
                  <div>
                    <h3>{attackMapping?.matrix || "MITRE ATT&CK Enterprise"}</h3>
                    <p>Derived from the current classification, URLs, attachments, authentication results, and sender metadata.</p>
                  </div>
                  <a
                    href="https://attack.mitre.org/matrices/enterprise/"
                    target="_blank"
                    rel="noreferrer"
                    className="attack-matrix-link"
                  >
                    Open matrix
                  </a>
                </div>
                <div className="attack-summary-stats">
                  <div className="attack-summary-stat">
                    <strong>{attackMapping?.techniques.length || 0}</strong>
                    <span>techniques</span>
                  </div>
                  <div className="attack-summary-stat">
                    <strong>{attackMapping?.tactics.length || 0}</strong>
                    <span>tactics</span>
                  </div>
                  <div className="attack-summary-stat">
                    <strong>{attackMapping?.context_codes.length || 0}</strong>
                    <span>context codes</span>
                  </div>
                </div>
                {attackMapping?.tactics && attackMapping.tactics.length > 0 ? (
                  <div className="attack-pill-list">
                    {attackMapping.tactics.map((tactic) => (
                      <span key={tactic} className="attack-pill attack-pill-strong">
                        {tactic}
                      </span>
                    ))}
                  </div>
                ) : null}
                {attackMapping?.context_codes && attackMapping.context_codes.length > 0 ? (
                  <div className="attack-meta-row">
                    <span className="attack-meta-label">Classification context</span>
                    <div className="attack-pill-list">
                      {attackMapping.context_codes.map((code) => (
                        <span key={code} className="attack-pill attack-pill-muted">
                          {code}
                        </span>
                      ))}
                    </div>
                  </div>
                ) : null}
                {attackMapping?.notes && attackMapping.notes.length > 0 ? (
                  <div className="attack-technique-block">
                    <h4>Notes</h4>
                    <ul className="attack-list">
                      {attackMapping.notes.map((note, index) => (
                        <li key={`attack-note-${index}`}>{note}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </section>

              {attackMapping?.techniques && attackMapping.techniques.length > 0 ? (
                <div className="attack-technique-list">
                  {attackMapping.techniques.map((technique) => (
                    <AttackTechniqueCard key={technique.technique_id} technique={technique} />
                  ))}
                </div>
              ) : (
                <section className="attack-empty-card">
                  <h3>No ATT&CK technique mapped</h3>
                  <p>
                    This report does not currently have enough delivery or deception evidence to assert a concrete ATT&CK
                    technique beyond its analyst classification.
                  </p>
                </section>
              )}
            </div>
          ) : null}

          {leftTab === "URLs" ? (
            <div className="detail-section url-tab">
              {urlRecords.length === 0 ? (
                <p>No URLs detected.</p>
              ) : (
                <>
                  <div className="url-summary">
                    <span className="url-summary-stat">
                      <strong>{urlRecords.length}</strong> URLs
                    </span>
                    <span className="url-summary-stat">
                      <strong>{uniqueUrlDomains}</strong> domains
                    </span>
                    <span className="url-summary-stat">
                      <strong>{redirectedUrlCount}</strong> redirected
                    </span>
                  </div>
                  <div className="url-record-list">
                    {urlRecords.map((record, index) => (
                      <section key={`${record.originalUrl}-${index}`} className="url-record">
                        <div className="url-record-header">
                          <h3>URL {index + 1}</h3>
                          <div className="url-record-badges">
                            <span className={`url-badge url-badge-${urlResolutionTone(record.resolutionStatus)}`}>
                              {urlResolutionLabel(record.resolutionStatus)}
                            </span>
                            {record.isShortener ? <span className="url-badge url-badge-neutral">Shortener</span> : null}
                            {record.domainChanged ? <span className="url-badge url-badge-warn">Domain changed</span> : null}
                            {record.suspiciousRedirect ? (
                              <span className="url-badge url-badge-bad">Suspicious redirect</span>
                            ) : null}
                          </div>
                        </div>
                        <div className="kv url-record-grid">
                          {renderFieldRow(
                            "Original URL",
                            <div className="url-field-content">
                              <a
                                href={record.originalUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="url-primary-link"
                              >
                                {record.originalUrl}
                              </a>
                              {renderCopyButton(record.originalUrl)}
                            </div>,
                            record.originalUrlArtifact,
                          )}
                          {renderFieldRow(
                            "Initial Domain",
                            record.initialDomain ? (
                              <div className="url-field-content">
                                <a
                                  href={`https://${record.initialDomain}`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="url-domain-link"
                                >
                                  {record.initialDomain}
                                </a>
                                {renderCopyButton(record.initialDomain)}
                              </div>
                            ) : (
                              "unknown"
                            ),
                            record.initialDomainArtifact,
                          )}
                          {renderFieldRow(
                            "Final URL",
                            record.finalUrl ? (
                              <div className="url-field-content">
                                <a
                                  href={record.finalUrl}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="url-primary-link"
                                >
                                  {record.finalUrl}
                                </a>
                                {renderCopyButton(record.finalUrl)}
                              </div>
                            ) : (
                              "unknown"
                            ),
                            record.finalUrlArtifact,
                          )}
                          {renderFieldRow(
                            "Final Domain",
                            record.finalDomain ? (
                              <div className="url-field-content">
                                <a
                                  href={`https://${record.finalDomain}`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="url-domain-link"
                                >
                                  {record.finalDomain}
                                </a>
                                {renderCopyButton(record.finalDomain)}
                              </div>
                            ) : (
                              "unknown"
                            ),
                            record.finalDomainArtifact,
                          )}
                          {renderFieldRow("Redirect Count", String(record.redirectCount))}
                          {renderFieldRow("Resolution Status", urlResolutionLabel(record.resolutionStatus))}
                          {record.resolutionError ? renderFieldRow("Resolution Error", record.resolutionError) : null}
                        </div>
                        {record.redirectChain.length > 0 ? (
                          <details className="url-chain-block">
                            <summary>Redirect chain</summary>
                            <div className="url-chain-list">
                              {record.redirectChain.map((hop) => (
                                <div key={`${hop.index}-${hop.url}`} className="url-chain-item">
                                  <span className="url-chain-status">{hop.status_code ?? "ERR"}</span>
                                  <div className="url-chain-content">
                                    <div>{hop.url}</div>
                                    {hop.location ? <div className="url-chain-next">Next: {hop.location}</div> : null}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </details>
                        ) : null}
                        {record.redirectChain.length === 0 && record.resolutionStatus === "disabled" ? (
                          <p className="url-chain-empty">Resolution was not run for this URL.</p>
                        ) : null}
                        {record.redirectChain.length === 0 &&
                        record.resolutionStatus !== "disabled" &&
                        record.resolutionStatus !== "no_redirect" ? (
                          <p className="url-chain-empty">No redirect hops were captured.</p>
                        ) : null}
                        {record.resolutionStatus === "no_redirect" ? (
                          <p className="url-chain-empty">No redirect observed.</p>
                        ) : null}
                      </section>
                    ))}
                  </div>
                </>
              )}
            </div>
          ) : null}

          {leftTab === "Attachments" ? (
            <div className="detail-section attachment-tab">
              {attachmentsLoading ? <p>Loading attachments...</p> : null}
              {attachmentsError ? <p>{attachmentsError}</p> : null}
              {!attachmentsLoading && !attachmentsError && attachments.length === 0 ? (
                <p>No attachments captured.</p>
              ) : null}
              {attachments.length > 0 ? (
                <div className="attachment-record-list">
                  {attachments.map((attachment, index) => (
                    <section key={attachment.id} className="attachment-record">
                      {(() => {
                        const attachmentNameArtifact = findArtifact("ATTACHMENT_NAME", attachment.filename);
                        const attachmentShaArtifact = findArtifact("ATTACHMENT_SHA256", attachment.sha256);
                        const nameFlagged = attachmentNameArtifact
                          ? stagedArtifactKeys.includes(artifactKey(attachmentNameArtifact))
                          : false;
                        const shaFlagged = attachmentShaArtifact
                          ? stagedArtifactKeys.includes(artifactKey(attachmentShaArtifact))
                          : false;

                        return (
                          <>
                      <div className="attachment-record-header">
                        <div className="attachment-record-title">
                          <span className="attachment-record-icon" aria-hidden="true">
                            📎
                          </span>
                          <h3>
                            ({index + 1}) {attachment.filename || "Unnamed attachment"}
                          </h3>
                        </div>
                        <div className="attachment-record-menu-wrap" ref={attachmentMenuId === attachment.id ? attachmentMenuRef : null}>
                          <button
                            type="button"
                            className="attachment-record-menu"
                            aria-label="Attachment options"
                            aria-expanded={attachmentMenuId === attachment.id}
                            onClick={() => {
                              setAttachmentFlagMenuId(null);
                              setAttachmentMenuId((current) => (current === attachment.id ? null : attachment.id));
                            }}
                          >
                            •••
                          </button>
                          {attachmentMenuId === attachment.id ? (
                            <div className="attachment-actions-dropdown" role="menu">
                              <div
                                className="attachment-action-submenu"
                                onMouseEnter={() => setAttachmentFlagMenuId(attachment.id)}
                                onMouseLeave={() => setAttachmentFlagMenuId((current) => (current === attachment.id ? null : current))}
                              >
                                <button
                                  className="report-action-item submenu-trigger"
                                  type="button"
                                  onClick={() =>
                                    setAttachmentFlagMenuId((current) => (current === attachment.id ? null : attachment.id))
                                  }
                                >
                                  Flag as malicious
                                  <span aria-hidden="true">▸</span>
                                </button>
                                {attachmentFlagMenuId === attachment.id ? (
                                  <div className="attachment-action-submenu-popout" role="menu">
                                    <button
                                      className="report-action-item checkbox-item"
                                      type="button"
                                      disabled={!attachmentNameArtifact}
                                      onClick={() => toggleArtifact(attachmentNameArtifact)}
                                    >
                                      <span className="checkbox-indicator" aria-hidden="true">
                                        {nameFlagged ? "☑" : "☐"}
                                      </span>
                                      Flag File name
                                    </button>
                                    <button
                                      className="report-action-item checkbox-item"
                                      type="button"
                                      disabled={!attachmentShaArtifact}
                                      onClick={() => toggleArtifact(attachmentShaArtifact)}
                                    >
                                      <span className="checkbox-indicator" aria-hidden="true">
                                        {shaFlagged ? "☑" : "☐"}
                                      </span>
                                      Flag SHA-256 hash
                                    </button>
                                  </div>
                                ) : null}
                              </div>
                              <button
                                className="report-action-item"
                                type="button"
                                disabled={downloadingAttachmentId === attachment.id}
                                onClick={() => void handleDownloadAttachment(attachment)}
                              >
                                {downloadingAttachmentId === attachment.id ? "Downloading..." : "Download"}
                              </button>
                            </div>
                          ) : null}
                        </div>
                      </div>
                      <div className="kv attachment-record-grid">
                        {renderFieldRow(
                          "File name",
                          displayFieldValue(attachment.filename),
                          attachmentNameArtifact,
                        )}
                        {renderFieldRow("File size", formatAttachmentSize(attachment.size_bytes))}
                        {renderFieldRow("File type", attachmentTypeLabel(attachment))}
                        {renderFieldRow(
                          "SHA-256",
                          displayFieldValue(attachment.sha256),
                          attachmentShaArtifact,
                        )}
                      </div>
                          </>
                        );
                      })()}
                    </section>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}

          {leftTab === "Transmission" ? (
            <div className="detail-section transmission-tab">
              {transmissionHops.length === 0 ? (
                <p>No Received headers found.</p>
              ) : (
                <div className="transmission-list">
                  {transmissionHops.map((hop) => (
                    <section key={hop.index} className="transmission-hop">
                      <div className="transmission-hop-head">
                        <h3>Hop {hop.index}</h3>
                        <span>{hop.timestamp || "Timestamp unavailable"}</span>
                      </div>
                      <div className="transmission-hop-body">
                        <div className="transmission-rail" aria-hidden="true" />
                        <div className="transmission-events">
                          {hop.receivedFrom ? (
                            <div className="transmission-event">
                              <span className="transmission-dot" aria-hidden="true" />
                              <div>
                                <strong>Received from</strong>
                                <span>{hop.receivedFrom}</span>
                              </div>
                            </div>
                          ) : null}
                          {hop.receivedBy ? (
                            <div className="transmission-event">
                              <span className="transmission-dot" aria-hidden="true" />
                              <div>
                                <strong>Received by</strong>
                                <span>{hop.receivedBy}</span>
                              </div>
                            </div>
                          ) : null}
                          {hop.protocol ? (
                            <div className="transmission-meta">
                              <strong>Protocol</strong>
                              <span>{hop.protocol}</span>
                            </div>
                          ) : null}
                          <details className="transmission-raw">
                            <summary>Show raw</summary>
                            <div className="mono detail-mono">{hop.raw}</div>
                          </details>
                        </div>
                      </div>
                    </section>
                  ))}
                </div>
              )}
            </div>
          ) : null}

          {leftTab === "X-Headers" ? (
            <div className="detail-section xheaders-tab">
              <div className="xheaders-search-row">
                <input
                  className="input xheaders-search"
                  type="search"
                  placeholder="Search X-headers"
                  value={xHeaderQuery}
                  onChange={(event) => setXHeaderQuery(event.target.value)}
                />
                <div className="xheaders-search-meta">
                  <span>{filteredXHeaderEntries.length} results</span>
                  {xHeaderQuery ? (
                    <button type="button" className="xheaders-clear" onClick={() => setXHeaderQuery("")}>
                      Clear
                    </button>
                  ) : null}
                </div>
              </div>
              {filteredXHeaderEntries.length > 0 ? (
                <div className="xheaders-list">
                  {filteredXHeaderEntries.map((entry, index) => (
                    <div key={`${entry.key}-${index}`} className="xheader-row">
                      <div className="xheader-key">{entry.key.toLowerCase()}</div>
                      <div className="xheader-value">{entry.value}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <p>{xHeaderEntries.length > 0 ? "No matching X-headers." : "No X- headers found."}</p>
              )}
            </div>
          ) : null}
        </div>

        <div className="panel report-detail-panel detail-mail-panel">
          <div className="tabs report-detail-tabs">
            {["Rendered", "HTML", "Plaintext", "Source"].map((tab) => (
              <button
                key={tab}
                className={`tab ${rightTab === tab ? "active" : ""}`}
                onClick={() => setRightTab(tab)}
                type="button"
              >
                {tab}
              </button>
            ))}
          </div>

          {rightTab === "Rendered" ? (
            latestReport?.body_html ? (
              <iframe
                className="mail-frame detail-mail-frame"
                title="rendered"
                sandbox=""
                srcDoc={latestReport.body_html}
              />
            ) : (
              <div className="detail-section">
                <p>No HTML body captured.</p>
              </div>
            )
          ) : null}

          {rightTab === "HTML" ? (
            <div className="mono detail-mono detail-section">
              {latestReport?.body_html || "No HTML body captured."}
            </div>
          ) : null}

          {rightTab === "Plaintext" ? (
            <div className="mono detail-mono detail-section">
              {latestReport?.body_text || "No text body captured."}
            </div>
          ) : null}

          {rightTab === "Source" ? (
            <div className="detail-section source-tab">
              <section className="source-card">
                <div className="source-card-header">
                  <div>
                    <h3>Original message</h3>
                    <p>The exact uploaded sample preserved during ingest.</p>
                  </div>
                  <button
                    className="resolve-button secondary"
                    type="button"
                    onClick={() => void handleDownloadOriginalMessage()}
                    disabled={!latestReport?.has_original_message || downloadingOriginalMessage}
                  >
                    {downloadingOriginalMessage ? "Downloading..." : "Download original sample"}
                  </button>
                </div>
                <div className="kv detail-kv source-card-grid">
                  <label>Filename</label>
                  <div>{displayFieldValue(latestReport?.original_filename)}</div>
                  <label>File type</label>
                  <div>{latestReport ? originalMessageTypeLabel(latestReport) : "unknown"}</div>
                  <label>Content type</label>
                  <div>{displayFieldValue(latestReport?.original_content_type)}</div>
                  <label>File size</label>
                  <div>{formatAttachmentSize(latestReport?.original_size_bytes)}</div>
                  <label>SHA-256</label>
                  <div>{displayFieldValue(latestReport?.original_sha256)}</div>
                </div>
              </section>

              <section className="source-card">
                <div className="source-card-header">
                  <div>
                    <h3>Raw source</h3>
                    <p>Decoded source content used for inline inspection.</p>
                  </div>
                </div>
                <div className="mono detail-mono source-card-mono">
                  {latestReport?.raw_source || "No raw source captured."}
                </div>
              </section>
            </div>
          ) : null}
        </div>
      </section>

      <ResolveDrawer
        open={drawerOpen && canResolve}
        report={report}
        attachments={attachments}
        preselectedArtifactKeys={stagedArtifactKeys}
        onClose={() => setDrawerOpen(false)}
        onResolved={(updatedReport) => {
          setReport(updatedReport);
          setStagedArtifactKeys((updatedReport.flagged_artifacts_json || []).map((artifact) => artifactKey(artifact)));
        }}
      />
    </main>
  );
}

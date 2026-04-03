import { ReactNode, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  Attachment,
  AuthStatus,
  FlaggedArtifact,
  Report,
  downloadReportEvidenceMarkdown,
  downloadReportEvidencePdf,
  fetchReport,
  fetchReportAttachments,
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

function toVirusTotalUrlId(url: string): string {
  if (typeof window === "undefined") {
    return Buffer.from(url, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  const bytes = new TextEncoder().encode(url);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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
  const router = useRouter();
  const { id } = router.query;
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [attachmentsLoading, setAttachmentsLoading] = useState(false);
  const [attachmentsError, setAttachmentsError] = useState<string | null>(null);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);
  const [exportingFormat, setExportingFormat] = useState<"md" | "pdf" | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [stagedArtifactKeys, setStagedArtifactKeys] = useState<string[]>([]);
  const [xHeaderQuery, setXHeaderQuery] = useState("");

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
    return buildReportArtifacts(report);
  }, [report]);

  const [leftTab, setLeftTab] = useState("Details");
  const [rightTab, setRightTab] = useState("Rendered");

  useEffect(() => {
    if (!report) {
      setStagedArtifactKeys([]);
      return;
    }
    setStagedArtifactKeys((report.flagged_artifacts_json || []).map((artifact) => artifactKey(artifact)));
  }, [report]);

  const findArtifact = (kind: FlaggedArtifact["kind"], value?: string | null) => {
    if (!hasValue(value)) return undefined;
    return availableArtifacts.find((artifact) => artifact.kind === kind && artifact.value === value!.trim());
  };

  const urlRecords = useMemo(
    () =>
      urls.map((url) => {
        const domain = domainFromUrl(url);
        return {
          url,
          domain,
          urlArtifact: findArtifact("URL", url),
          domainArtifact: domain ? findArtifact("URL_DOMAIN", domain) : undefined,
          virusTotalUrl: `https://www.virustotal.com/gui/url/${toVirusTotalUrlId(url)}`,
        };
      }),
    [urls, availableArtifacts],
  );
  const uniqueUrlDomains = useMemo(
    () => new Set(urlRecords.map((record) => record.domain).filter(Boolean)).size,
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

  const handleEvidenceExport = async (format: "md" | "pdf") => {
    if (!report || exportingFormat) return;
    setExportingFormat(format);
    setExportError(null);
    try {
      const download =
        format === "md" ? await downloadReportEvidenceMarkdown(report.id) : await downloadReportEvidencePdf(report.id);
      const url = window.URL.createObjectURL(download.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = download.filename || `report-${report.id}-evidence.${format}`;
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
          <Link href="/reports">&lt;- Back to uploads</Link>
          <h1>{report.subject || "(no subject)"}</h1>
          <p>Report #{report.id}</p>
        </div>
        <div className="report-detail-actions">
          <button
            className="tab export-action"
            type="button"
            onClick={() => void handleEvidenceExport("md")}
            disabled={!!exportingFormat}
          >
            {exportingFormat === "md" ? "Exporting .md..." : "Export .md"}
          </button>
          <button
            className="tab export-action"
            type="button"
            onClick={() => void handleEvidenceExport("pdf")}
            disabled={!!exportingFormat}
          >
            {exportingFormat === "pdf" ? "Exporting .pdf..." : "Export .pdf"}
          </button>
          {report.status === "OPEN" && canResolve ? (
            <button className="resolve-button" type="button" onClick={() => setDrawerOpen(true)} disabled={updating}>
              Resolve
            </button>
          ) : null}
          {report.status !== "OPEN" ? (
            <span className={report.status === "PHISHING" ? "badge phishing" : "badge"}>{report.status}</span>
          ) : null}
          {report.status !== "OPEN" && canReopen ? (
            <button className="resolve-button secondary" type="button" onClick={handleReopen} disabled={updating}>
              {updating ? "Reopening..." : "Reopen"}
            </button>
          ) : null}
        </div>
      </header>
      {exportError ? <p className="report-detail-error">{exportError}</p> : null}

      <section className="split report-detail-split">
        <div className="panel report-detail-panel">
          <div className="tabs report-detail-tabs">
            {["Details", "Authentication", "URLs", "Attachments", "Transmission", "X-Headers"].map((tab) => (
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
                  </div>
                  <div className="url-record-list">
                    {urlRecords.map((record, index) => (
                      <section key={`${record.url}-${index}`} className="url-record">
                        <div className="kv url-record-grid">
                          {renderFieldRow(
                            "URL",
                            <a
                              href={record.url}
                              target="_blank"
                              rel="noreferrer"
                              className="url-primary-link"
                            >
                              {record.url}
                            </a>,
                            record.urlArtifact,
                          )}
                          {renderFieldRow(
                            "Domain",
                            record.domain ? (
                              <a
                                href={`https://${record.domain}`}
                                target="_blank"
                                rel="noreferrer"
                                className="url-domain-link"
                              >
                                {record.domain}
                              </a>
                            ) : (
                              "unknown"
                            ),
                            record.domainArtifact,
                          )}
                          {renderFieldRow(
                            "VirusTotal",
                            <a
                              href={record.virusTotalUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="url-action-link"
                            >
                              Open lookup
                            </a>,
                          )}
                        </div>
                      </section>
                    ))}
                  </div>
                </>
              )}
            </div>
          ) : null}

          {leftTab === "Attachments" ? (
            <div className="detail-section">
              {attachmentsLoading ? <p>Loading attachments...</p> : null}
              {attachmentsError ? <p>{attachmentsError}</p> : null}
              {!attachmentsLoading && !attachmentsError && attachments.length === 0 ? (
                <p>No attachments captured.</p>
              ) : null}
              {attachments.length > 0 ? (
                <table className="table">
                  <thead>
                    <tr>
                      <th>Filename</th>
                      <th>Type</th>
                      <th>Size</th>
                      <th>SHA-256</th>
                      <th>Storage key</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attachments.map((attachment) => (
                      <tr key={attachment.id}>
                        <td>{attachment.filename || "-"}</td>
                        <td>{attachment.content_type || "-"}</td>
                        <td>{attachment.size_bytes ?? "-"}</td>
                        <td>{attachment.sha256 || "-"}</td>
                        <td>{attachment.s3_key || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
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
            <div className="mono detail-mono detail-section">
              {latestReport?.raw_source || "No raw source captured."}
            </div>
          ) : null}
        </div>
      </section>

      <ResolveDrawer
        open={drawerOpen && canResolve}
        report={report}
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

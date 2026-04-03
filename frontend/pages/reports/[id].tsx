import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  Attachment,
  AuthStatus,
  Report,
  downloadReportEvidenceMarkdown,
  downloadReportEvidencePdf,
  fetchReport,
  fetchReportAttachments,
  reopenReport,
} from "../../lib/api";
import ResolveDrawer from "../../components/ResolveDrawer";
import { useAuth } from "../../lib/auth-context";

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

function renderFixedAuthField(label: string, value?: string | null, fallback = "unknown") {
  return (
    <>
      <label>{label}</label>
      <div>{displayAuthValue(value, fallback)}</div>
    </>
  );
}

function renderAuthField(label: string, value?: string | null) {
  if (!hasValue(value)) return null;
  return (
    <>
      <label>{label}</label>
      <div>{value}</div>
    </>
  );
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
  const receivedHeaders = Object.entries(latestHeaders)
    .filter(([key]) => key.toLowerCase() === "received")
    .map(([, value]) => String(value));
  const xHeaders = Object.entries(latestHeaders).filter(([key]) => key.toLowerCase().startsWith("x-"));

  const [leftTab, setLeftTab] = useState("Details");
  const [rightTab, setRightTab] = useState("Rendered");

  const handleReopen = async () => {
    if (!report) return;
    setUpdating(true);
    try {
      const updated = await reopenReport(report.id);
      setReport(updated);
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
              <label>From</label>
              <div>{latestReport?.from_addr || "-"}</div>
              <label>Display Name</label>
              <div>{latestReport?.from_display_name || "-"}</div>
              <label>Sender</label>
              <div>{latestReport?.sender || "-"}</div>
              <label>To</label>
              <div>{latestReport?.to_addrs?.join(", ") || "-"}</div>
              <label>Cc</label>
              <div>{latestReport?.cc_addrs?.join(", ") || "-"}</div>
              <label>In-Reply-To</label>
              <div>{latestReport?.in_reply_to || "-"}</div>
              <label>Timestamp</label>
              <div>
                {latestReport?.received_at
                  ? new Date(latestReport.received_at).toLocaleString()
                  : latestReport?.date
                  ? new Date(latestReport.date).toLocaleString()
                  : "-"}
              </div>
              <label>Reply-To</label>
              <div>{latestReport?.reply_to?.join(", ") || "-"}</div>
              <label>Message ID</label>
              <div>{latestReport?.message_id || "-"}</div>
              <label>Return-Path</label>
              <div>{latestReport?.return_path || "-"}</div>
              <label>Originating IP + rDNS</label>
              <div>
                {latestReport?.originating_ip || "-"}
                {latestReport?.originating_rdns ? ` (${latestReport.originating_rdns})` : ""}
              </div>
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
                  {renderFixedAuthField(
                    "Originating IP",
                    formatSpfOriginatingIp(authSummary?.spf.originating_ip, authSummary?.spf.source_header),
                  )}
                  {renderFixedAuthField("rDNS", authSummary?.spf.originating_rdns)}
                  {renderFixedAuthField("Return-Path domain", authSummary?.spf.return_path_domain)}
                  {renderFixedAuthField(
                    "SPF record",
                    authSummary?.spf.dns_record ||
                      spfRecord ||
                      extractParenthesized(authSummary?.raw_headers.received_spf || authSummary?.spf.raw),
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
                  {renderFixedAuthField(
                    "Selector",
                    formatSelectorDisplay(primarySignature?.selector, primarySignature?.signing_domain),
                  )}
                  {renderFixedAuthField("Signing domain", primarySignature?.signing_domain)}
                  {renderFixedAuthField("Algorithm", primarySignature?.algorithm)}
                  {renderFixedAuthField("Verification", displayAuthValue(primarySignature?.result).toUpperCase())}
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
                          {renderFixedAuthField(
                            "Selector",
                            formatSelectorDisplay(signature.selector, signature.signing_domain),
                          )}
                          {renderFixedAuthField("Signing domain", signature.signing_domain)}
                          {renderFixedAuthField("Algorithm", signature.algorithm)}
                          {renderFixedAuthField("Verification", displayAuthValue(signature.result).toUpperCase())}
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
                  {renderFixedAuthField("From domain", authSummary?.dmarc.header_from)}
                  {renderFixedAuthField(
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
                  {renderAuthField("Instance", authSummary?.arc.instance)}
                  {renderAuthField("Seal result", authSummary?.arc.seal_result)}
                  {renderAuthField("Message signature result", authSummary?.arc.message_signature_result)}
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
            <div className="detail-section">
              {urls.length === 0 ? <p>No URLs detected.</p> : null}
              <div className="url-list">
                {urls.map((url) => (
                  <span key={url} className="url-pill">
                    {url}
                  </span>
                ))}
              </div>
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
            <div className="mono detail-mono detail-section">
              {receivedHeaders.length > 0 ? receivedHeaders.join("\n\n") : "No Received headers found."}
            </div>
          ) : null}

          {leftTab === "X-Headers" ? (
            <div className="mono detail-mono detail-section">
              {xHeaders.length > 0
                ? xHeaders.map(([key, value]) => `${key}: ${String(value)}`).join("\n")
                : "No X- headers found."}
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
        onClose={() => setDrawerOpen(false)}
        onResolved={(updatedReport) => setReport(updatedReport)}
      />
    </main>
  );
}

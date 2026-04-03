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

function renderAuthField(label: string, value?: string | null) {
  if (!hasValue(value)) return null;
  return (
    <>
      <label>{label}</label>
      <div>{value}</div>
    </>
  );
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
              <div className="auth-overview-grid">
                {[
                  { label: "SPF", status: authSummary?.overview.spf },
                  { label: "DKIM", status: authSummary?.overview.dkim },
                  { label: "DMARC", status: authSummary?.overview.dmarc },
                  { label: "ARC", status: authSummary?.overview.arc },
                ].map((item) => (
                  <div key={item.label} className="auth-overview-card">
                    <span className="auth-overview-label">{item.label}</span>
                    <span className={authStatusClass(item.status)}>{authStatusLabel(item.status)}</span>
                  </div>
                ))}
              </div>

              <section className={`auth-card auth-card-${authStatusTone(authSummary?.spf.result)}`}>
                <div className="auth-card-header">
                  <div>
                    <p className="auth-card-eyebrow">Envelope sender validation</p>
                    <h3>SPF</h3>
                  </div>
                  <span className={authStatusClass(authSummary?.spf.result)}>{authStatusLabel(authSummary?.spf.result)}</span>
                </div>
                <div className="kv detail-kv auth-kv">
                  {renderAuthField("Source", authSummary?.spf.source_header)}
                  {renderAuthField("Auth server", authSummary?.spf.authserv_id)}
                  {renderAuthField("Receiver", authSummary?.spf.receiver)}
                  {renderAuthField("Envelope sender", authSummary?.spf.smtp_mailfrom)}
                  {renderAuthField("HELO/EHLO", authSummary?.spf.smtp_helo)}
                  {renderAuthField("Return-Path domain", authSummary?.spf.return_path_domain)}
                  {renderAuthField("Originating IP", authSummary?.spf.originating_ip)}
                  {renderAuthField("Originating rDNS", authSummary?.spf.originating_rdns)}
                </div>
              </section>

              <section className={`auth-card auth-card-${authStatusTone(authSummary?.dkim.result)}`}>
                <div className="auth-card-header">
                  <div>
                    <p className="auth-card-eyebrow">Message integrity signatures</p>
                    <h3>DKIM</h3>
                  </div>
                  <span className={authStatusClass(authSummary?.dkim.result)}>{authStatusLabel(authSummary?.dkim.result)}</span>
                </div>
                <div className="auth-card-meta">
                  {authSummary?.dkim.signature_count
                    ? `${authSummary.dkim.signature_count} signature${authSummary.dkim.signature_count === 1 ? "" : "s"}`
                    : "No DKIM signatures parsed"}
                </div>
                {authSummary?.dkim.signatures?.length ? (
                  <div className="auth-stack">
                    {authSummary.dkim.signatures.map((signature, index) => (
                      <div key={`${signature.selector || "sig"}-${index}`} className="auth-subcard">
                        <div className="auth-subcard-header">
                          <strong>Signature {index + 1}</strong>
                          <span className={authStatusClass(signature.result)}>{authStatusLabel(signature.result)}</span>
                        </div>
                        <div className="kv detail-kv auth-kv">
                          {renderAuthField("Signing domain", signature.signing_domain)}
                          {renderAuthField("Identity", signature.identity)}
                          {renderAuthField("Selector", signature.selector)}
                          {renderAuthField("Algorithm", signature.algorithm)}
                          {renderAuthField("Canonicalization", signature.canonicalization)}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </section>

              <section className={`auth-card auth-card-${authStatusTone(authSummary?.dmarc.result)}`}>
                <div className="auth-card-header">
                  <div>
                    <p className="auth-card-eyebrow">Alignment and policy result</p>
                    <h3>DMARC</h3>
                  </div>
                  <span className={authStatusClass(authSummary?.dmarc.result)}>{authStatusLabel(authSummary?.dmarc.result)}</span>
                </div>
                <div className="kv detail-kv auth-kv">
                  {renderAuthField("Header.From domain", authSummary?.dmarc.header_from)}
                  {renderAuthField("Aligned From domain", authSummary?.dmarc.aligned_from_domain)}
                  {renderAuthField("Aligned MailFrom domain", authSummary?.dmarc.aligned_mailfrom_domain)}
                  {renderAuthField("Policy", authSummary?.dmarc.policy)}
                </div>
              </section>

              <section className={`auth-card auth-card-${authStatusTone(authSummary?.arc.result)}`}>
                <div className="auth-card-header">
                  <div>
                    <p className="auth-card-eyebrow">Forwarding chain preservation</p>
                    <h3>ARC</h3>
                  </div>
                  <span className={authStatusClass(authSummary?.arc.result)}>{authStatusLabel(authSummary?.arc.result)}</span>
                </div>
                <div className="kv detail-kv auth-kv">
                  {renderAuthField("Instance", authSummary?.arc.instance)}
                  {renderAuthField("Seal result", authSummary?.arc.seal_result)}
                  {renderAuthField("Message signature result", authSummary?.arc.message_signature_result)}
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

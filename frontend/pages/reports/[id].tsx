import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  Attachment,
  Report,
  downloadReportEvidenceMarkdown,
  downloadReportEvidencePdf,
  fetchReport,
  fetchReportAttachments,
  reopenReport,
} from "../../lib/api";
import ResolveDrawer from "../../components/ResolveDrawer";
import { useAuth } from "../../lib/auth-context";

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
  const authHeader =
    (latestHeaders["Authentication-Results"] as string) ||
    (latestHeaders["authentication-results"] as string) ||
    "";
  const authResults = useMemo(() => {
    const lower = authHeader.toLowerCase();
    const get = (key: string) => {
      const match = lower.match(new RegExp(`${key}=([a-z0-9_-]+)`));
      return match ? match[1] : "unknown";
    };
    return {
      spf: authHeader ? get("spf") : "unknown",
      dkim: authHeader ? get("dkim") : "unknown",
      dmarc: authHeader ? get("dmarc") : "unknown",
      raw: authHeader,
    };
  }, [authHeader]);
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
              <div className="kv detail-kv">
                <label>SPF</label>
                <div>{authResults.spf}</div>
                <label>DKIM</label>
                <div>{authResults.dkim}</div>
                <label>DMARC</label>
                <div>{authResults.dmarc}</div>
              </div>
              <div className="mono detail-mono">
                {authResults.raw ? authResults.raw : "No Authentication-Results header found."}
              </div>
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

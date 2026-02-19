import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  CLASSIFICATION_CODES,
  ClassificationCode,
  Report,
  fetchReport,
  updateReport,
} from "../../lib/api";

function isClassificationCode(value: string): value is ClassificationCode {
  return (CLASSIFICATION_CODES as readonly string[]).includes(value);
}

export default function ReportDetailPage() {
  const router = useRouter();
  const { id } = router.query;
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
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
  }, [id]);

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

  const handleStatusChange = async (value: Report["status"]) => {
    if (!report) return;
    setUpdating(true);
    try {
      const updated = await updateReport(report.id, { status: value });
      setReport(updated);
    } finally {
      setUpdating(false);
    }
  };

  const handleClassificationChange = async (value: string) => {
    if (!report) return;
    setUpdating(true);
    try {
      const nextCode = value === "UNCLASSIFIED" ? null : isClassificationCode(value) ? value : null;
      const updated = await updateReport(report.id, {
        classification_code: nextCode,
      });
      setReport(updated);
    } finally {
      setUpdating(false);
    }
  };

  if (loading) {
    return (
      <main>
        <p>Loading...</p>
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
    <main className="full">
      <header>
        <div>
          <Link href="/reports">&lt;- Back to uploads</Link>
          <h1>{report.subject || "(no subject)"}</h1>
          <p>Report #{report.id}</p>
        </div>
        <select
          className="select"
          value={report.status}
          disabled={updating}
          onChange={(event) => handleStatusChange(event.target.value as Report["status"])}
        >
          <option value="OPEN">OPEN</option>
          <option value="BENIGN">BENIGN</option>
          <option value="PHISHING">PHISHING</option>
        </select>
      </header>

      <section className="split">
        <div className="panel">
          <div className="tabs">
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
            <div className="kv">
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
              <label>Classification</label>
              <div>
                <select
                  className="select"
                  value={latestReport?.classification_code || "UNCLASSIFIED"}
                  disabled={updating}
                  onChange={(event) => handleClassificationChange(event.target.value)}
                >
                  <option value="UNCLASSIFIED">UNCLASSIFIED</option>
                  {CLASSIFICATION_CODES.map((code) => (
                    <option key={code} value={code}>
                      {code}
                    </option>
                  ))}
                </select>
              </div>
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
            <div>
              <div className="kv" style={{ marginBottom: 10 }}>
                <label>SPF</label>
                <div>{authResults.spf}</div>
                <label>DKIM</label>
                <div>{authResults.dkim}</div>
                <label>DMARC</label>
                <div>{authResults.dmarc}</div>
              </div>
              <div className="mono">
                {authResults.raw ? authResults.raw : "No Authentication-Results header found."}
              </div>
            </div>
          ) : null}

          {leftTab === "URLs" ? (
            <div>
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
            <p>No attachments captured in v0.</p>
          ) : null}

          {leftTab === "Transmission" ? (
            <div className="mono">
              {receivedHeaders.length > 0 ? receivedHeaders.join("\n\n") : "No Received headers found."}
            </div>
          ) : null}

          {leftTab === "X-Headers" ? (
            <div className="mono">
              {xHeaders.length > 0
                ? xHeaders.map(([key, value]) => `${key}: ${String(value)}`).join("\n")
                : "No X- headers found."}
            </div>
          ) : null}
        </div>

        <div className="panel" style={{ display: "flex", flexDirection: "column", minHeight: "100%" }}>
          <div className="tabs">
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
                className="mail-frame"
                title="rendered"
                sandbox=""
                srcDoc={latestReport.body_html}
                style={{ flex: 1 }}
              />
            ) : (
              <p>No HTML body captured.</p>
            )
          ) : null}

          {rightTab === "HTML" ? (
            <div className="mono">{latestReport?.body_html || "No HTML body captured."}</div>
          ) : null}

          {rightTab === "Plaintext" ? (
            <div className="mono">{latestReport?.body_text || "No text body captured."}</div>
          ) : null}

          {rightTab === "Source" ? (
            <div className="mono">{latestReport?.raw_source || "No raw source captured."}</div>
          ) : null}
        </div>
      </section>
    </main>
  );
}

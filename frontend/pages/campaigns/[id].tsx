import Link from "next/link";
import { useRouter } from "next/router";
import { useEffect, useState } from "react";

import {
  Campaign,
  CampaignEvent,
  Report,
  downloadCampaignEvidenceMarkdown,
  downloadCampaignEvidencePdf,
  fetchCampaign,
  fetchCampaignEvents,
  fetchCampaignReports,
  lockCampaign,
  splitCampaign,
  unlockCampaign,
} from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

export default function CampaignDetailPage() {
  const router = useRouter();
  const { id } = router.query;
  const campaignId = Number(id);

  const { hasPermission } = useAuth();
  const canRead = hasPermission("campaigns.read");
  const canWrite = hasPermission("campaigns.write");

  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [reports, setReports] = useState<Report[]>([]);
  const [events, setEvents] = useState<CampaignEvent[]>([]);
  const [selectedReportIds, setSelectedReportIds] = useState<number[]>([]);
  const [newCampaignName, setNewCampaignName] = useState("");
  const [lockReason, setLockReason] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [exportingFormat, setExportingFormat] = useState<"md" | "pdf" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    if (!campaignId) return;
    let active = true;
    setLoading(true);
    Promise.all([
      fetchCampaign(campaignId),
      fetchCampaignReports(campaignId, { limit: 500 }),
      fetchCampaignEvents(campaignId, 200),
    ])
      .then(([campaignData, reportData, eventData]) => {
        if (!active) return;
        setCampaign(campaignData);
        setReports(reportData);
        setEvents(eventData);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err instanceof Error ? err.message : "Failed to load campaign");
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [canRead, campaignId, reloadTick]);

  if (!canRead) {
    return (
      <main className="full">
        <h1>Campaign</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  if (loading) {
    return (
      <main className="full">
        <p>Loading...</p>
      </main>
    );
  }

  if (!campaign || error) {
    return (
      <main className="full">
        <p>{error || "Campaign not found."}</p>
        <Link href="/campaigns">Back to campaigns</Link>
      </main>
    );
  }

  const handleCampaignEvidenceExport = async (format: "md" | "pdf") => {
    if (!campaign || exportingFormat) return;
    setExportingFormat(format);
    setError(null);
    try {
      const download =
        format === "md"
          ? await downloadCampaignEvidenceMarkdown(campaign.id)
          : await downloadCampaignEvidencePdf(campaign.id);
      const url = window.URL.createObjectURL(download.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = download.filename || `campaign-${campaign.id}-evidence.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export campaign evidence.");
    } finally {
      setExportingFormat(null);
    }
  };

  return (
    <main className="full">
      <header>
        <div>
          <Link href="/campaigns">&lt;- Back to campaigns</Link>
          <h1>Campaign #{campaign.id}</h1>
          <p>{campaign.name || campaign.campaign_key}</p>
        </div>
        <div className="report-detail-actions">
          <button
            className="tab export-action"
            type="button"
            onClick={() => void handleCampaignEvidenceExport("md")}
            disabled={!!exportingFormat}
          >
            {exportingFormat === "md" ? "Exporting .md..." : "Export .md"}
          </button>
          <button
            className="tab export-action"
            type="button"
            onClick={() => void handleCampaignEvidenceExport("pdf")}
            disabled={!!exportingFormat}
          >
            {exportingFormat === "pdf" ? "Exporting .pdf..." : "Export .pdf"}
          </button>
        </div>
      </header>

      <section className="card" style={{ marginBottom: 14 }}>
        <div className="meta-grid">
          <div className="meta-card">
            <strong>Reports</strong>
            <p>{campaign.report_count}</p>
          </div>
          <div className="meta-card">
            <strong>Confidence</strong>
            <p>{campaign.confidence_score != null ? campaign.confidence_score.toFixed(3) : "-"}</p>
          </div>
          <div className="meta-card">
            <strong>Locked</strong>
            <p>{campaign.is_locked ? "Yes" : "No"}</p>
          </div>
          <div className="meta-card">
            <strong>Last Seen</strong>
            <p>{campaign.last_seen ? new Date(campaign.last_seen).toLocaleString() : "-"}</p>
          </div>
        </div>

        {canWrite ? (
          <div style={{ marginTop: 12, display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <input
              className="input"
              placeholder="Lock reason (optional)"
              value={lockReason}
              onChange={(event) => setLockReason(event.target.value)}
            />
            {campaign.is_locked ? (
              <button
                className="tab"
                type="button"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await unlockCampaign(campaign.id);
                    setReloadTick((tick) => tick + 1);
                  } catch (err) {
                    setError(err instanceof Error ? err.message : "Unlock failed.");
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Unlock Campaign
              </button>
            ) : (
              <button
                className="tab"
                type="button"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await lockCampaign(campaign.id, lockReason || null);
                    setLockReason("");
                    setReloadTick((tick) => tick + 1);
                  } catch (err) {
                    setError(err instanceof Error ? err.message : "Lock failed.");
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Lock Campaign
              </button>
            )}
          </div>
        ) : null}
      </section>

      {canWrite ? (
        <section className="card" style={{ marginBottom: 14 }}>
          <h2 style={{ marginTop: 0 }}>Split selected reports into new campaign</h2>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <input
              className="input"
              placeholder="New campaign name (optional)"
              value={newCampaignName}
              onChange={(event) => setNewCampaignName(event.target.value)}
            />
            <button
              className="tab"
              type="button"
              disabled={busy || selectedReportIds.length === 0}
              onClick={async () => {
                setBusy(true);
                try {
                  await splitCampaign({
                    source_campaign_id: campaign.id,
                    report_ids: selectedReportIds,
                    new_campaign_name: newCampaignName || null,
                  });
                  setSelectedReportIds([]);
                  setNewCampaignName("");
                  setReloadTick((tick) => tick + 1);
                } catch (err) {
                  setError(err instanceof Error ? err.message : "Split failed.");
                } finally {
                  setBusy(false);
                }
              }}
            >
              Split Selected
            </button>
          </div>
        </section>
      ) : null}

      <section className="card" style={{ marginBottom: 14 }}>
        <h2 style={{ marginTop: 0 }}>Reports</h2>
        {reports.length === 0 ? <p>No reports in this campaign.</p> : null}
        {reports.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                {canWrite ? <th>Select</th> : null}
                <th>ID</th>
                <th>Subject</th>
                <th>From</th>
                <th>Status</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id}>
                  {canWrite ? (
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedReportIds.includes(report.id)}
                        onChange={(event) => {
                          setSelectedReportIds((current) =>
                            event.target.checked
                              ? [...new Set([...current, report.id])]
                              : current.filter((id) => id !== report.id)
                          );
                        }}
                      />
                    </td>
                  ) : null}
                  <td>
                    <Link href={`/reports/${report.id}`}>#{report.id}</Link>
                  </td>
                  <td>{report.subject || "(no subject)"}</td>
                  <td>{report.from_addr || "-"}</td>
                  <td>{report.status}</td>
                  <td>{new Date(report.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>

      <section className="card">
        <h2 style={{ marginTop: 0 }}>Campaign events</h2>
        {events.length === 0 ? <p>No campaign events yet.</p> : null}
        {events.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Actor</th>
                <th>Report</th>
                <th>From</th>
                <th>To</th>
                <th>Score</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td>{event.action}</td>
                  <td>{event.actor_snapshot}</td>
                  <td>{event.report_id || "-"}</td>
                  <td>{event.from_campaign_id || "-"}</td>
                  <td>{event.to_campaign_id || "-"}</td>
                  <td>{event.score != null ? event.score.toFixed(3) : "-"}</td>
                  <td>{new Date(event.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </main>
  );
}

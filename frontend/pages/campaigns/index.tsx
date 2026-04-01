import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { Campaign, fetchCampaigns, mergeCampaigns, reclusterCampaigns } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

export default function CampaignListPage() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("campaigns.read");
  const canWrite = hasPermission("campaigns.write");
  const canRun = hasPermission("campaigns.run");

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [selectedCampaignIds, setSelectedCampaignIds] = useState<number[]>([]);
  const [targetCampaignId, setTargetCampaignId] = useState("");
  const [reclusterResult, setReclusterResult] = useState<string | null>(null);
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    fetchCampaigns({ q: query, limit: 200 })
      .then((data) => {
        if (!active) return;
        setCampaigns(data);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || "Failed to load campaigns");
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [canRead, query, reloadTick]);

  const mergeCandidates = useMemo(
    () => selectedCampaignIds.map((id) => campaigns.find((campaign) => campaign.id === id)).filter(Boolean) as Campaign[],
    [selectedCampaignIds, campaigns]
  );

  if (!canRead) {
    return (
      <main className="full">
        <h1>Campaigns</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  return (
    <main className="full">
      <header>
        <div>
          <h1>Campaigns</h1>
          <p>Automatically grouped phishing campaigns with analyst correction workflows.</p>
        </div>
      </header>

      <section className="card" style={{ marginBottom: 14 }}>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <input
            className="input"
            style={{ flex: "1 1 320px" }}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search campaign key or name"
          />
          {canRun ? (
            <button
              className="tab"
              type="button"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setReclusterResult(null);
                try {
                  const result = await reclusterCampaigns({});
                  setReclusterResult(
                    `Recluster complete: processed=${result.processed_reports}, reassigned=${result.reassigned_reports}, new=${result.created_campaigns}, skipped_manual=${result.skipped_manual_reports}`
                  );
                  setReloadTick((tick) => tick + 1);
                } catch (err) {
                  setReclusterResult(err instanceof Error ? err.message : "Recluster failed.");
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Running..." : "Run Recluster"}
            </button>
          ) : null}
        </div>
        {reclusterResult ? <p style={{ marginTop: 8 }}>{reclusterResult}</p> : null}
      </section>

      {canWrite ? (
        <section className="card" style={{ marginBottom: 14 }}>
          <h2 style={{ marginTop: 0 }}>Merge campaigns</h2>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <input
              className="input"
              placeholder="Target campaign ID"
              value={targetCampaignId}
              onChange={(event) => setTargetCampaignId(event.target.value)}
            />
            <button
              className="tab"
              type="button"
              disabled={busy || selectedCampaignIds.length === 0 || !targetCampaignId}
              onClick={async () => {
                const targetId = Number(targetCampaignId);
                if (!targetId) return;
                setBusy(true);
                try {
                  await mergeCampaigns({
                    source_campaign_ids: selectedCampaignIds,
                    target_campaign_id: targetId,
                  });
                  setSelectedCampaignIds([]);
                  setTargetCampaignId("");
                  setReloadTick((tick) => tick + 1);
                } catch (err) {
                  setError(err instanceof Error ? err.message : "Merge failed");
                } finally {
                  setBusy(false);
                }
              }}
            >
              Merge Selected
            </button>
          </div>
          {mergeCandidates.length > 0 ? (
            <p style={{ marginTop: 8 }}>
              Selected source campaigns: {mergeCandidates.map((item) => `#${item.id}`).join(", ")}
            </p>
          ) : null}
        </section>
      ) : null}

      <section className="card">
        {loading ? <p>Loading...</p> : null}
        {error ? <p>{error}</p> : null}
        {!loading && campaigns.length === 0 ? <p>No campaigns yet.</p> : null}
        {campaigns.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                {canWrite ? <th>Select</th> : null}
                <th>ID</th>
                <th>Name</th>
                <th>Reports</th>
                <th>Confidence</th>
                <th>Locked</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((campaign) => (
                <tr key={campaign.id}>
                  {canWrite ? (
                    <td>
                      <input
                        type="checkbox"
                        checked={selectedCampaignIds.includes(campaign.id)}
                        onChange={(event) => {
                          setSelectedCampaignIds((current) =>
                            event.target.checked
                              ? [...new Set([...current, campaign.id])]
                              : current.filter((id) => id !== campaign.id)
                          );
                        }}
                      />
                    </td>
                  ) : null}
                  <td>
                    <Link href={`/campaigns/${campaign.id}`}>#{campaign.id}</Link>
                  </td>
                  <td>{campaign.name || "-"}</td>
                  <td>{campaign.report_count}</td>
                  <td>{campaign.confidence_score != null ? campaign.confidence_score.toFixed(3) : "-"}</td>
                  <td>{campaign.is_locked ? "Yes" : "No"}</td>
                  <td>{campaign.last_seen ? new Date(campaign.last_seen).toLocaleString() : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </main>
  );
}

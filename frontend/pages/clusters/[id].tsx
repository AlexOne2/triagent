import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { ClusterDetail, updateClusterStatus, fetchCluster } from "../../lib/api";

export default function ClusterDetailPage() {
  const router = useRouter();
  const { id } = router.query;
  const [cluster, setCluster] = useState<ClusterDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let active = true;
    setLoading(true);
    fetchCluster(id as string)
      .then((data) => {
        if (!active) return;
        setCluster(data);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || "Failed to load cluster");
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
    if (!cluster) return [];
    const all = cluster.reports.flatMap((report) => report.urls_json || []);
    return Array.from(new Set(all));
  }, [cluster]);

  const latestReport = cluster?.reports?.[0] ?? null;

  const handleStatusChange = async (value: ClusterDetail["status"]) => {
    if (!cluster) return;
    const updated = await updateClusterStatus(cluster.id, value);
    setCluster({ ...cluster, status: updated.status });
  };

  if (loading) {
    return (
      <main>
        <p>Loading...</p>
      </main>
    );
  }

  if (error || !cluster) {
    return (
      <main>
        <p>{error || "Cluster not found"}</p>
        <Link href="/clusters">Back to inbox</Link>
      </main>
    );
  }

  return (
    <main>
      <header>
        <div>
          <Link href="/clusters">&lt;- Back to inbox</Link>
          <h1>{cluster.subject_norm || "(no subject)"}</h1>
          <p>Cluster #{cluster.id}</p>
        </div>
        <select
          className="select"
          value={cluster.status}
          onChange={(event) => handleStatusChange(event.target.value as ClusterDetail["status"])}
        >
          <option value="OPEN">OPEN</option>
          <option value="BENIGN">BENIGN</option>
          <option value="PHISHING">PHISHING</option>
        </select>
      </header>

      <section className="meta-grid">
        <div className="meta-card">
          <h2>{cluster.report_count}</h2>
          <p>Reports</p>
        </div>
        <div className="meta-card">
          <h2>{cluster.risk_score}</h2>
          <p>Risk score</p>
        </div>
        <div className="meta-card">
          <h2>{cluster.from_domain || "-"}</h2>
          <p>Sender domain</p>
        </div>
        <div className="meta-card">
          <h2>{new Date(cluster.last_seen).toLocaleString()}</h2>
          <p>Last seen</p>
        </div>
      </section>

      <section className="card" style={{ marginTop: 20 }}>
        <h2>Extracted URLs</h2>
        {urls.length === 0 ? <p>No URLs detected.</p> : null}
        <div className="url-list">
          {urls.map((url) => (
            <span key={url} className="url-pill">
              {url}
            </span>
          ))}
        </div>
      </section>

      <section className="card" style={{ marginTop: 20 }}>
        <h2>Reports</h2>
        <table className="table">
          <thead>
            <tr>
              <th>Date</th>
              <th>From</th>
              <th>To</th>
              <th>Subject</th>
              <th>Reporter Hash</th>
            </tr>
          </thead>
          <tbody>
            {cluster.reports.map((report) => (
              <tr key={report.id}>
                <td>{report.date ? new Date(report.date).toLocaleString() : "-"}</td>
                <td>{report.from_addr || "-"}</td>
                <td>{report.to_addrs?.join(", ") || "-"}</td>
                <td>{report.subject || "-"}</td>
                <td>{report.reporter_hash || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card" style={{ marginTop: 20 }}>
        <h2>Latest Body Preview</h2>
        <div className="report-body">
          {latestReport?.body_text || latestReport?.body_html || "No body captured."}
        </div>
      </section>

      <section className="card" style={{ marginTop: 20 }}>
        <h2>Headers JSON</h2>
        <div className="report-body">
          {latestReport?.headers_json
            ? JSON.stringify(latestReport.headers_json, null, 2)
            : "No headers captured."}
        </div>
      </section>
    </main>
  );
}

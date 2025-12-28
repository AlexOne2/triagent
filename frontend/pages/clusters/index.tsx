import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Cluster, fetchClusters } from "../../lib/api";

const statusClass = (status: Cluster["status"]) => {
  if (status === "PHISHING") return "badge phishing";
  if (status === "BENIGN") return "badge";
  return "badge open";
};

export default function ClusterList() {
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    fetchClusters(query)
      .then((data) => {
        if (!active) return;
        setClusters(data);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || "Failed to load clusters");
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query]);

  const summary = useMemo(() => {
    const phishing = clusters.filter((c) => c.status === "PHISHING").length;
    const open = clusters.filter((c) => c.status === "OPEN").length;
    return { phishing, open };
  }, [clusters]);

  return (
    <main>
      <header>
        <div>
          <h1>Phishing Triage Inbox</h1>
          <p>Clustered reports with risk scores and quick status controls.</p>
        </div>
        <input
          className="input"
          placeholder="Search subject or domain"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </header>

      <div className="meta-grid">
        <div className="meta-card">
          <h2>{clusters.length}</h2>
          <p>Total clusters</p>
        </div>
        <div className="meta-card">
          <h2>{summary.open}</h2>
          <p>Open investigations</p>
        </div>
        <div className="meta-card">
          <h2>{summary.phishing}</h2>
          <p>Confirmed phishing</p>
        </div>
      </div>

      <section className="card report-table">
        <h2>Clusters</h2>
        {loading ? <p>Loading...</p> : null}
        {error ? <p>{error}</p> : null}
        {!loading && clusters.length === 0 ? <p>No clusters yet.</p> : null}
        {!loading && clusters.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Subject</th>
                <th>From Domain</th>
                <th>Reports</th>
                <th>Last Seen</th>
                <th>Risk</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {clusters.map((cluster) => (
                <tr key={cluster.id}>
                  <td>
                    <Link href={`/clusters/${cluster.id}`}>
                      {cluster.subject_norm || "(no subject)"}
                    </Link>
                  </td>
                  <td>{cluster.from_domain || "-"}</td>
                  <td>{cluster.report_count}</td>
                  <td>{new Date(cluster.last_seen).toLocaleString()}</td>
                  <td>{cluster.risk_score}</td>
                  <td>
                    <span className={statusClass(cluster.status)}>{cluster.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </main>
  );
}

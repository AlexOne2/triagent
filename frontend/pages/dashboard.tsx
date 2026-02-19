import Link from "next/link";
import { useEffect, useState } from "react";
import { fetchReportStats, ReportStats } from "../lib/api";

export default function Dashboard() {
  const [stats, setStats] = useState<ReportStats | null>(null);

  useEffect(() => {
    let active = true;
    fetchReportStats()
      .then((data) => {
        if (!active) return;
        setStats(data);
      })
      .catch(() => {
        if (!active) return;
        setStats(null);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <main>
      <header>
        <div>
          <h1>Dashboard</h1>
        </div>
        <Link href="/reports" className="tab">
          Go to Uploads
        </Link>
      </header>

      <div className="meta-grid">
        <div className="meta-card">
          <h2>{stats ? stats.total : "-"}</h2>
          <p>Total reports</p>
        </div>
        <div className="meta-card">
          <h2>{stats ? stats.open : "-"}</h2>
          <p>Open reports</p>
        </div>
      </div>

      <section className="card" style={{ marginTop: 20 }}>
        <p>This page will show rollups, trends, and KPIs in a future iteration.</p>
      </section>
    </main>
  );
}

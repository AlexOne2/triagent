import { useEffect, useState } from "react";
import Link from "next/link";
import { Report, fetchReports } from "../lib/api";

export default function InTray() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    fetchReports(query, undefined, "AUTO")
      .then((data) => {
        if (!active) return;
        setReports(data);
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query]);

  return (
    <main className="full">
      <header>
        <div>
          <h1>In-tray</h1>
          <p>Automatically collected entries.</p>
        </div>
      </header>

      <input
        className="input"
        placeholder="Search subject or sender"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        style={{ marginTop: 12, width: "100%" }}
      />

      <section className="card report-table" style={{ marginTop: 16 }}>
        {loading ? <p>Loading...</p> : null}
        {!loading && reports.length === 0 ? <p>No auto-ingested reports yet.</p> : null}
        {reports.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>From</th>
                <th>To</th>
                <th>Subject</th>
                <th>Status</th>
                <th>Date uploaded</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.id}>
                  <td>{report.from_addr || "-"}</td>
                  <td>{report.to_addrs?.join(", ") || "-"}</td>
                  <td>
                    <Link href={`/reports/${report.id}`}>
                      {report.subject || "(no subject)"}
                    </Link>
                  </td>
                  <td>
                    <span className={report.status === "PHISHING" ? "badge phishing" : "badge"}>
                      {report.status}
                    </span>
                  </td>
                  <td>{new Date(report.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </main>
  );
}

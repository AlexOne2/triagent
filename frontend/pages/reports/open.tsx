import { useEffect, useState } from "react";
import Link from "next/link";
import { Report, fetchReports } from "../../lib/api";

export default function OpenReports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    fetchReports(undefined, "OPEN", "UPLOAD")
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
  }, []);

  return (
    <main>
      <header>
        <div>
          <Link href="/reports">&lt;- Back to uploads</Link>
          <h1>Open Uploads</h1>
          <p>Manually uploaded reports awaiting triage.</p>
        </div>
        <Link href="/reports/closed" className="tab">
          View Closed
        </Link>
      </header>

      <section className="card report-table">
        {loading ? <p>Loading...</p> : null}
        {!loading && reports.length === 0 ? <p>No open reports.</p> : null}
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
                    <span className="badge open">{report.status}</span>
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

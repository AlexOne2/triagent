import { useEffect, useState } from "react";
import Link from "next/link";
import { Report, fetchReports } from "../../lib/api";

export default function ClosedReports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    Promise.all([fetchReports(undefined, "BENIGN", "UPLOAD"), fetchReports(undefined, "PHISHING", "UPLOAD")])
      .then(([benign, phishing]) => {
        if (!active) return;
        setReports([...benign, ...phishing]);
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
          <h1>Closed Uploads</h1>
          <p>Benign and phishing determinations for uploads.</p>
        </div>
        <Link href="/reports/open" className="tab">
          View Open
        </Link>
      </header>

      <section className="card report-table">
        {loading ? <p>Loading...</p> : null}
        {!loading && reports.length === 0 ? <p>No closed reports.</p> : null}
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

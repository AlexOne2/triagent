import { useEffect, useState } from "react";
import Link from "next/link";
import { Report, fetchReports, uploadEml } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

const statusClass = (status: Report["status"]) => {
  if (status === "PHISHING") return "badge phishing";
  if (status === "BENIGN") return "badge";
  return "badge open";
};

export default function ReportList() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("reports.read");
  const canIngest = hasPermission("reports.ingest");
  const [reports, setReports] = useState<Report[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    fetchReports(query, "OPEN", "UPLOAD")
      .then((data) => {
        if (!active) return;
        setReports(data);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || "Failed to load reports");
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query, reloadTick, canRead]);

  if (!canRead) {
    return (
      <main className="full">
        <h1>Uploads</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  return (
    <main className="full">
      <header>
        <div>
          <h1>Uploads</h1>
        </div>
      </header>
      {canIngest ? (
        <div
          className={`upload-zone ${dragActive ? "active" : ""}`}
          onDragOver={(event) => {
            event.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={async (event) => {
            event.preventDefault();
            setDragActive(false);
            const file = event.dataTransfer.files?.[0];
            if (!file) return;
            setUploading(true);
            setUploadStatus("Uploading...");
            try {
              await uploadEml(file);
              setUploadStatus("Uploaded .eml successfully.");
              setReloadTick((tick) => tick + 1);
            } catch (err) {
              setUploadStatus(err instanceof Error ? err.message : "Upload failed.");
            } finally {
              setUploading(false);
            }
          }}
        >
          <p>Upload .eml files to ingest reported mail.</p>
          <input
            type="file"
            accept=".eml"
            disabled={uploading}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (!file) return;
              setUploading(true);
              setUploadStatus("Uploading...");
              try {
                await uploadEml(file);
                setUploadStatus("Uploaded .eml successfully.");
                setReloadTick((tick) => tick + 1);
              } catch (err) {
                setUploadStatus(err instanceof Error ? err.message : "Upload failed.");
              } finally {
                setUploading(false);
                event.target.value = "";
              }
            }}
          />
          <div className="upload-actions">
            <button
              type="button"
              className="tab"
              onClick={() => {
                const input = document.querySelector<HTMLInputElement>(".upload-zone input[type='file']");
                input?.click();
              }}
            >
              {uploading ? "Uploading..." : "Choose file"}
            </button>
            <span>{uploadStatus || "Drag & drop or choose a file."}</span>
          </div>
        </div>
      ) : null}

      <input
        className="input"
        placeholder="Search subject or sender"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        style={{ marginTop: 16, width: "100%" }}
      />

      <section className="card report-table">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <h2>Open Uploads</h2>
          <Link href="/reports/closed" className="tab">
            View Closed
          </Link>
        </div>
        {loading ? <p>Loading...</p> : null}
        {error ? <p>{error}</p> : null}
        {!loading && reports.length === 0 ? <p>No reports yet.</p> : null}
        {!loading && reports.length > 0 ? (
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
                    <span className={statusClass(report.status)}>{report.status}</span>
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

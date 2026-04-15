import { useEffect, useState } from "react";
import Link from "next/link";
import ReportListPagination from "../../components/ReportListPagination";
import ReportSearchToolbar from "../../components/ReportSearchToolbar";
import { ClassificationCode, FileIngestItem, Report, fetchReports, uploadReportFiles } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

const PAGE_SIZE = 50;

const statusClass = (status: Report["status"]) => {
  if (status === "PHISHING") return "badge phishing";
  if (status === "BENIGN") return "badge";
  return "badge open";
};

const sortReportsByCreatedAtDesc = (items: Report[]) =>
  [...items].sort((left, right) => {
    const leftTime = new Date(left.created_at).getTime();
    const rightTime = new Date(right.created_at).getTime();
    if (leftTime !== rightTime) {
      return rightTime - leftTime;
    }
    return right.id - left.id;
  });

export default function ReportList() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("reports.read");
  const canIngest = hasPermission("reports.ingest");
  const [reports, setReports] = useState<Report[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [draftQuery, setDraftQuery] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState<Report["status"] | "">("");
  const [classificationFilter, setClassificationFilter] = useState<ClassificationCode | "">("");
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [uploadResults, setUploadResults] = useState<FileIngestItem[]>([]);
  const [uploading, setUploading] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const uploadFiles = async (files: File[]) => {
    if (files.length === 0) {
      return;
    }
    const allowed = files.filter((file) => {
      const lowered = file.name.toLowerCase();
      return lowered.endsWith(".eml") || lowered.endsWith(".msg");
    });
    if (allowed.length === 0) {
      throw new Error("Unsupported file type. Upload .eml or .msg files.");
    }
    const batch = await uploadReportFiles(allowed);
    setUploadResults(batch.items);
    setUploadStatus(
      `Processed ${batch.items.length} files: ${batch.ingested_count} ingested, ${batch.failed_count} failed.`
    );
    if (batch.ingested_count > 0) {
      setReloadTick((tick) => tick + 1);
    }
  };

  useEffect(() => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true);
    fetchReports({
      query,
      status: statusFilter || undefined,
      source: "UPLOAD",
      classificationCode: classificationFilter || undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    })
      .then((data) => {
        if (!active) return;
        setReports(sortReportsByCreatedAtDesc(data.items));
        setTotalCount(data.total);
        setError(null);
      })
      .catch((err) => {
        if (!active) return;
        setError(err.message || "Failed to load reports");
        setTotalCount(0);
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query, page, statusFilter, classificationFilter, reloadTick, canRead]);

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
            const droppedFiles = Array.from(event.dataTransfer.files || []);
            if (!droppedFiles.length) return;
            setUploading(true);
            setUploadStatus("Uploading...");
            try {
              await uploadFiles(droppedFiles);
            } catch (err) {
              setUploadStatus(err instanceof Error ? err.message : "Upload failed.");
            } finally {
              setUploading(false);
            }
          }}
        >
          <p>Upload .eml or .msg files to ingest reported mail.</p>
          <input
            type="file"
            accept=".eml,.msg"
            multiple
            disabled={uploading}
            onChange={async (event) => {
              const pickedFiles = Array.from(event.target.files || []);
              if (!pickedFiles.length) return;
              setUploading(true);
              setUploadStatus("Uploading...");
              try {
                await uploadFiles(pickedFiles);
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
            <span>{uploadStatus || "Drag & drop files or choose files."}</span>
          </div>
          {uploadResults.length > 0 ? (
            <table className="table" style={{ marginTop: 8 }}>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Status</th>
                  <th>Report</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {uploadResults.map((item, index) => (
                  <tr key={`${item.filename}-${index}`}>
                    <td>{item.filename}</td>
                    <td>{item.status}</td>
                    <td>{item.report_id ?? "-"}</td>
                    <td>{item.error_message || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </div>
      ) : null}

      <ReportSearchToolbar
        draftQuery={draftQuery}
        onDraftQueryChange={setDraftQuery}
        onSubmit={() => {
          setPage(0);
          setQuery(draftQuery.trim());
        }}
        onClear={() => {
          setDraftQuery("");
          setQuery("");
          setPage(0);
          setStatusFilter("");
          setClassificationFilter("");
        }}
        status={statusFilter}
        onStatusChange={(value) => {
          setPage(0);
          setStatusFilter(value);
        }}
        classification={classificationFilter}
        onClassificationChange={(value) => {
          setPage(0);
          setClassificationFilter(value);
        }}
        resultCount={totalCount}
        resultLabel={totalCount === 1 ? "upload" : "uploads"}
      />

      <section className="card report-table">
        <h2>Uploads</h2>
        {loading ? <p>Loading...</p> : null}
        {error ? <p>{error}</p> : null}
        {!loading && reports.length === 0 ? <p>No uploads match the current search.</p> : null}
        {!loading && reports.length > 0 ? (
          <>
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
            <ReportListPagination
              total={totalCount}
              offset={page * PAGE_SIZE}
              limit={PAGE_SIZE}
              itemLabel={totalCount === 1 ? "upload" : "uploads"}
              onPrevious={() => setPage((current) => Math.max(0, current - 1))}
              onNext={() => setPage((current) => current + 1)}
              hasPrevious={page > 0}
              hasNext={(page + 1) * PAGE_SIZE < totalCount}
            />
          </>
        ) : null}
      </section>
    </main>
  );
}

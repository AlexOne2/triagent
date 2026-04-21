import { useEffect, useRef, useState } from "react";
import ReportListPagination from "../../components/ReportListPagination";
import ReportQueueTable from "../../components/ReportQueueTable";
import ReportSearchToolbar from "../../components/ReportSearchToolbar";
import {
  ClassificationCode,
  FileIngestItem,
  Report,
  TriageBucket,
  fetchReports,
  uploadReportFiles,
} from "../../lib/api";
import { useAuth } from "../../lib/auth-context";
import { getTriageBucketMeta } from "../../lib/triage";

const PAGE_SIZE = 50;

const sortReports = (items: Report[], triageBuckets: TriageBucket[]) =>
  [...items].sort((left, right) => {
    if (
      triageBuckets.length === 1 &&
      triageBuckets[0] === "NEEDS_INVESTIGATION"
    ) {
      const leftPriority = left.triage_assessment?.investigation_priority_score || 0;
      const rightPriority = right.triage_assessment?.investigation_priority_score || 0;
      if (leftPriority !== rightPriority) {
        return rightPriority - leftPriority;
      }
    }
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
  const [triageFilters, setTriageFilters] = useState<TriageBucket[]>([]);
  const [statusFilters, setStatusFilters] = useState<Report["status"][]>([]);
  const [classificationFilters, setClassificationFilters] = useState<ClassificationCode[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [uploadResults, setUploadResults] = useState<FileIngestItem[]>([]);
  const [uploading, setUploading] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

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
      statuses: statusFilters.length > 0 ? statusFilters : undefined,
      source: "UPLOAD",
      classificationCodes: classificationFilters.length > 0 ? classificationFilters : undefined,
      triageBuckets: triageFilters.length > 0 ? triageFilters : undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    })
      .then((data) => {
        if (!active) return;
        setReports(sortReports(data.items, triageFilters));
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
  }, [query, page, triageFilters, statusFilters, classificationFilters, reloadTick, canRead]);

  if (!canRead) {
    return (
      <main className="full">
        <h1>Uploads</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  const triageSummary =
    triageFilters.length === 0
      ? "All uploaded entries are shown. Use filters to narrow to specific triage lanes."
      : `Filtered to ${triageFilters.map((bucket) => getTriageBucketMeta(bucket).label).join(", ")}.`;

  return (
    <main className="full queue-page">
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
            ref={fileInputRef}
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
                fileInputRef.current?.click();
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
          setTriageFilters([]);
          setStatusFilters([]);
          setClassificationFilters([]);
        }}
        statuses={statusFilters}
        onStatusesChange={(value) => {
          setPage(0);
          setStatusFilters(value);
        }}
        triageBuckets={triageFilters}
        onTriageBucketsChange={(value) => {
          setPage(0);
          setTriageFilters(value);
        }}
        classifications={classificationFilters}
        onClassificationsChange={(value) => {
          setPage(0);
          setClassificationFilters(value);
        }}
        resultCount={totalCount}
        resultLabel={totalCount === 1 ? "upload" : "uploads"}
      />

      <section className="card report-table">
        <div className="queue-section-head">
          <div>
            <h2>Uploads</h2>
            <p>{triageSummary}</p>
          </div>
          <span className="queue-section-count">
            {totalCount} {totalCount === 1 ? "upload" : "uploads"}
          </span>
        </div>

        {error ? <p>{error}</p> : null}
        {!error ? <ReportQueueTable reports={reports} loading={loading} emptyMessage="No uploads match the current search." /> : null}

        {!error && reports.length > 0 ? (
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
        ) : null}
      </section>
    </main>
  );
}

import { useEffect, useState } from "react";
import Link from "next/link";
import ReportListPagination from "../components/ReportListPagination";
import ReportSearchToolbar from "../components/ReportSearchToolbar";
import { ClassificationCode, Report, fetchReports } from "../lib/api";
import { useAuth } from "../lib/auth-context";

const PAGE_SIZE = 50;

const sortReportsByCreatedAtDesc = (items: Report[]) =>
  [...items].sort((left, right) => {
    const leftTime = new Date(left.created_at).getTime();
    const rightTime = new Date(right.created_at).getTime();
    if (leftTime !== rightTime) {
      return rightTime - leftTime;
    }
    return right.id - left.id;
  });

export default function InTray() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("reports.read");
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [draftQuery, setDraftQuery] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState<Report["status"] | "">("");
  const [classificationFilter, setClassificationFilter] = useState<ClassificationCode | "">("");
  const [totalCount, setTotalCount] = useState(0);

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
      source: "AUTO",
      classificationCode: classificationFilter || undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    })
      .then((data) => {
        if (!active) return;
        setReports(sortReportsByCreatedAtDesc(data.items));
        setTotalCount(data.total);
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query, page, statusFilter, classificationFilter, canRead]);

  if (!canRead) {
    return (
      <main className="full">
        <h1>In-tray</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  return (
    <main className="full">
      <header>
        <div>
          <h1>In-tray</h1>
          <p>Automatically collected entries.</p>
        </div>
      </header>

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
        resultLabel={totalCount === 1 ? "message" : "messages"}
      />

      <section className="card report-table" style={{ marginTop: 16 }}>
        {loading ? <p>Loading...</p> : null}
        {!loading && reports.length === 0 ? <p>No auto-ingested reports match the current search.</p> : null}
        {reports.length > 0 ? (
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
                      <span className={report.status === "PHISHING" ? "badge phishing" : "badge"}>
                        {report.status}
                      </span>
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
              itemLabel={totalCount === 1 ? "message" : "messages"}
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

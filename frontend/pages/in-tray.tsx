import { useEffect, useState } from "react";
import ReportListPagination from "../components/ReportListPagination";
import ReportQueueTable from "../components/ReportQueueTable";
import ReportSearchToolbar from "../components/ReportSearchToolbar";
import { ClassificationCode, Report, TriageBucket, fetchReports } from "../lib/api";
import { useAuth } from "../lib/auth-context";
import { getTriageBucketMeta } from "../lib/triage";

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

export default function InTray() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("reports.read");
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [draftQuery, setDraftQuery] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [triageFilters, setTriageFilters] = useState<TriageBucket[]>([]);
  const [statusFilters, setStatusFilters] = useState<Report["status"][]>([]);
  const [classificationFilters, setClassificationFilters] = useState<ClassificationCode[]>([]);
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
      statuses: statusFilters.length > 0 ? statusFilters : undefined,
      source: "AUTO",
      classificationCodes: classificationFilters.length > 0 ? classificationFilters : undefined,
      triageBuckets: triageFilters.length > 0 ? triageFilters : undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    })
      .then((data) => {
        if (!active) return;
        setReports(sortReports(data.items, triageFilters));
        setTotalCount(data.total);
      })
      .finally(() => {
        if (!active) return;
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query, page, triageFilters, statusFilters, classificationFilters, canRead]);

  if (!canRead) {
    return (
      <main className="full">
        <h1>In-tray</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  const triageSummary =
    triageFilters.length === 0
      ? "All auto-reported entries are shown. Use filters to narrow to specific triage lanes."
      : `Filtered to ${triageFilters.map((bucket) => getTriageBucketMeta(bucket).label).join(", ")}.`;

  return (
    <main className="full queue-page">
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
        resultLabel={totalCount === 1 ? "message" : "messages"}
      />

      <section className="card report-table">
        <div className="queue-section-head">
          <div>
            <h2>Auto-reported queue</h2>
            <p>{triageSummary}</p>
          </div>
          <span className="queue-section-count">
            {totalCount} {totalCount === 1 ? "message" : "messages"}
          </span>
        </div>

        <ReportQueueTable
          reports={reports}
          loading={loading}
          emptyMessage="No auto-reported reports match the current search."
        />

        {reports.length > 0 ? (
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
        ) : null}
      </section>
    </main>
  );
}

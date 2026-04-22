import { useEffect, useState } from "react";
import ReportListPagination from "../components/ReportListPagination";
import ReportQueueTable from "../components/ReportQueueTable";
import ReportSearchToolbar from "../components/ReportSearchToolbar";
import { Report, fetchReports } from "../lib/api";
import { useAuth } from "../lib/auth-context";
import { VisibleTriageBucket, expandVisibleTriageBuckets } from "../lib/triage";
import { usePersistedQueueFilters } from "../lib/use-persisted-queue-filters";

const PAGE_SIZE = 50;

const sortReports = (items: Report[], triageBuckets: VisibleTriageBucket[]) =>
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
  const [page, setPage] = useState(0);
  const [totalCount, setTotalCount] = useState(0);
  const {
    ready,
    draftQuery,
    setDraftQuery,
    query,
    applyDraftQuery,
    clearFilters,
    triageFilters,
    setTriageFilters,
    statusFilters,
    setStatusFilters,
    classificationFilters,
    setClassificationFilters,
  } = usePersistedQueueFilters("in-tray");

  useEffect(() => {
    if (!canRead) {
      setLoading(false);
      return;
    }
    if (!ready) {
      return;
    }
    let active = true;
    setLoading(true);
    const expandedTriageBuckets = expandVisibleTriageBuckets(triageFilters);
    fetchReports({
      query,
      statuses: statusFilters.length > 0 ? statusFilters : undefined,
      source: "AUTO",
      classificationCodes: classificationFilters.length > 0 ? classificationFilters : undefined,
      triageBuckets: expandedTriageBuckets.length > 0 ? expandedTriageBuckets : undefined,
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
  }, [query, page, triageFilters, statusFilters, classificationFilters, canRead, ready]);

  if (!canRead) {
    return (
      <main className="full">
        <h1>In-tray</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

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
          applyDraftQuery();
        }}
        onClear={() => {
          setPage(0);
          clearFilters();
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

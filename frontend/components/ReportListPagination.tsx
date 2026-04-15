type ReportListPaginationProps = {
  total: number;
  offset: number;
  limit: number;
  itemLabel: string;
  onPrevious: () => void;
  onNext: () => void;
  hasPrevious: boolean;
  hasNext: boolean;
};

export default function ReportListPagination({
  total,
  offset,
  limit,
  itemLabel,
  onPrevious,
  onNext,
  hasPrevious,
  hasNext,
}: ReportListPaginationProps) {
  const rangeStart = total === 0 ? 0 : offset + 1;
  const rangeEnd = total === 0 ? 0 : Math.min(offset + limit, total);

  return (
    <div className="report-list-pagination">
      <div className="report-list-pagination-summary">
        Showing {rangeStart}-{rangeEnd} of {total} {itemLabel}
      </div>
      <div className="report-list-pagination-actions">
        <button
          type="button"
          className="report-list-pagination-button"
          onClick={onPrevious}
          disabled={!hasPrevious}
        >
          Previous
        </button>
        <button
          type="button"
          className="report-list-pagination-button"
          onClick={onNext}
          disabled={!hasNext}
        >
          Next
        </button>
      </div>
    </div>
  );
}

import { FormEvent, useEffect, useRef, useState } from "react";
import { CLASSIFICATION_CODES, ClassificationCode, Report } from "../lib/api";
import { TRIAGE_BUCKET_ORDER, VisibleTriageBucket, getTriageBucketMeta } from "../lib/triage";

const STATUS_OPTIONS: Array<{ value: Report["status"]; label: string }> = [
  { value: "OPEN", label: "Open" },
  { value: "PHISHING", label: "Phishing" },
  { value: "BENIGN", label: "Benign" },
];

type ReportSearchToolbarProps = {
  draftQuery: string;
  onDraftQueryChange: (value: string) => void;
  onSubmit: () => void;
  onClear: () => void;
  statuses: Report["status"][];
  onStatusesChange: (value: Report["status"][]) => void;
  triageBuckets: VisibleTriageBucket[];
  onTriageBucketsChange: (value: VisibleTriageBucket[]) => void;
  classifications: ClassificationCode[];
  onClassificationsChange: (value: ClassificationCode[]) => void;
  resultCount: number;
  resultLabel: string;
};

export default function ReportSearchToolbar({
  draftQuery,
  onDraftQueryChange,
  onSubmit,
  onClear,
  statuses,
  onStatusesChange,
  triageBuckets,
  onTriageBucketsChange,
  classifications,
  onClassificationsChange,
  resultCount,
  resultLabel,
}: ReportSearchToolbarProps) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const filterAnchorRef = useRef<HTMLDivElement | null>(null);
  const activeFilterCount = statuses.length + triageBuckets.length + classifications.length;
  const hasSearchState = Boolean(draftQuery.trim()) || activeFilterCount > 0;

  useEffect(() => {
    const handlePointerDown = (event: MouseEvent) => {
      if (!filterAnchorRef.current) return;
      if (filterAnchorRef.current.contains(event.target as Node)) return;
      setFiltersOpen(false);
    };

    document.addEventListener("mousedown", handlePointerDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
    };
  }, []);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit();
  };

  const toggleStatus = (value: Report["status"]) => {
    if (statuses.includes(value)) {
      onStatusesChange(statuses.filter((item) => item !== value));
      return;
    }
    onStatusesChange([...statuses, value]);
  };

  const toggleClassification = (value: ClassificationCode) => {
    if (classifications.includes(value)) {
      onClassificationsChange(classifications.filter((item) => item !== value));
      return;
    }
    onClassificationsChange([...classifications, value]);
  };

  const toggleTriageBucket = (value: VisibleTriageBucket) => {
    if (triageBuckets.includes(value)) {
      onTriageBucketsChange(triageBuckets.filter((item) => item !== value));
      return;
    }
    onTriageBucketsChange([...triageBuckets, value]);
  };

  return (
    <section className="card search-toolbar">
      <div className="search-toolbar-header">
        <div>
          <div className="search-toolbar-kicker">Queue Search</div>
        </div>
        <div className="search-toolbar-meta">
          <span className="search-toolbar-results">
            {resultCount} {resultLabel}
          </span>
          {hasSearchState ? (
            <button type="button" className="search-toolbar-clear" onClick={onClear}>
              Clear
            </button>
          ) : null}
        </div>
      </div>

      <form className="search-toolbar-form" onSubmit={handleSubmit}>
        <label className="search-toolbar-input-shell" aria-label="Search reports">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path
              fill="currentColor"
              d="M10.5 4a6.5 6.5 0 1 0 4.06 11.58l4.43 4.43 1.41-1.41-4.43-4.43A6.5 6.5 0 0 0 10.5 4m0 2a4.5 4.5 0 1 1 0 9a4.5 4.5 0 0 1 0-9"
            />
          </svg>
          <input
            className="input search-toolbar-input"
            placeholder="Search subject, address, domain, IP, URL, filename, or SHA-256"
            value={draftQuery}
            onChange={(event) => onDraftQueryChange(event.target.value)}
          />
        </label>
        <button type="submit" className="resolve-button search-toolbar-submit">
          Search
        </button>
      </form>

      <div className="search-toolbar-row">
        <div className="search-toolbar-controls">
          <div className="search-toolbar-filter-anchor" ref={filterAnchorRef}>
            <button
              type="button"
              className={`search-toolbar-filter-trigger ${filtersOpen ? "open" : ""}`.trim()}
              onClick={() => setFiltersOpen((current) => !current)}
            >
              <span>Filters ({activeFilterCount})</span>
              <svg viewBox="0 0 20 20" aria-hidden="true">
                <path
                  fill="currentColor"
                  d={filtersOpen ? "M5.2 12.8L10 8l4.8 4.8-1.4 1.4L10 10.8l-3.4 3.4z" : "M5.2 7.2L10 12l4.8-4.8-1.4-1.4L10 9.2 6.6 5.8z"}
                />
              </svg>
            </button>

            {filtersOpen ? (
              <div className="search-toolbar-filter-panel">
                <div className="search-toolbar-filter-column">
                  <div className="search-toolbar-filter-column-header">
                    <span>Status ({statuses.length})</span>
                    {statuses.length > 0 ? (
                      <button type="button" className="search-toolbar-filter-clear" onClick={() => onStatusesChange([])}>
                        Clear
                      </button>
                    ) : null}
                  </div>
                  <div className="search-toolbar-filter-list">
                    {STATUS_OPTIONS.map((option) => (
                      <label key={option.value} className="search-toolbar-filter-option">
                        <input
                          type="checkbox"
                          checked={statuses.includes(option.value)}
                          onChange={() => toggleStatus(option.value)}
                        />
                        <span>{option.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="search-toolbar-filter-column">
                  <div className="search-toolbar-filter-column-header">
                    <span>Triage ({triageBuckets.length})</span>
                    {triageBuckets.length > 0 ? (
                      <button
                        type="button"
                        className="search-toolbar-filter-clear"
                        onClick={() => onTriageBucketsChange([])}
                      >
                        Clear
                      </button>
                    ) : null}
                  </div>
                  <div className="search-toolbar-filter-list">
                    {TRIAGE_BUCKET_ORDER.map((bucket) => (
                      <label key={bucket} className="search-toolbar-filter-option">
                        <input
                          type="checkbox"
                          checked={triageBuckets.includes(bucket)}
                          onChange={() => toggleTriageBucket(bucket)}
                        />
                        <span>{getTriageBucketMeta(bucket).label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="search-toolbar-filter-column search-toolbar-filter-column-scroll">
                  <div className="search-toolbar-filter-column-header">
                    <span>Classification ({classifications.length})</span>
                    {classifications.length > 0 ? (
                      <button
                        type="button"
                        className="search-toolbar-filter-clear"
                        onClick={() => onClassificationsChange([])}
                      >
                        Clear
                      </button>
                    ) : null}
                  </div>
                  <div className="search-toolbar-filter-list">
                    {CLASSIFICATION_CODES.map((code) => (
                      <label key={code} className="search-toolbar-filter-option">
                        <input
                          type="checkbox"
                          checked={classifications.includes(code)}
                          onChange={() => toggleClassification(code)}
                        />
                        <span>{code}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>

      {activeFilterCount > 0 ? (
        <div className="search-toolbar-chip-row">
          {statuses.map((status) => (
            <button key={status} type="button" className="search-toolbar-chip" onClick={() => toggleStatus(status)}>
              Status: {STATUS_OPTIONS.find((item) => item.value === status)?.label || status}
              <span aria-hidden="true">×</span>
            </button>
          ))}
          {triageBuckets.map((bucket) => (
            <button key={bucket} type="button" className="search-toolbar-chip" onClick={() => toggleTriageBucket(bucket)}>
              Queue: {getTriageBucketMeta(bucket).label}
              <span aria-hidden="true">×</span>
            </button>
          ))}
          {classifications.map((classification) => (
            <button
              key={classification}
              type="button"
              className="search-toolbar-chip"
              onClick={() => toggleClassification(classification)}
            >
              Classification: {classification}
              <span aria-hidden="true">×</span>
            </button>
          ))}
        </div>
      ) : null}
    </section>
  );
}

import { FormEvent } from "react";
import { CLASSIFICATION_CODES, ClassificationCode, Report } from "../lib/api";

type ReportSearchToolbarProps = {
  draftQuery: string;
  onDraftQueryChange: (value: string) => void;
  onSubmit: () => void;
  onClear: () => void;
  status: Report["status"] | "";
  onStatusChange: (value: Report["status"] | "") => void;
  classification: ClassificationCode | "";
  onClassificationChange: (value: ClassificationCode | "") => void;
  resultCount: number;
  resultLabel: string;
};

export default function ReportSearchToolbar({
  draftQuery,
  onDraftQueryChange,
  onSubmit,
  onClear,
  status,
  onStatusChange,
  classification,
  onClassificationChange,
  resultCount,
  resultLabel,
}: ReportSearchToolbarProps) {
  const activeFilterCount = Number(Boolean(status)) + Number(Boolean(classification));
  const hasSearchState = Boolean(draftQuery.trim()) || activeFilterCount > 0;

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit();
  };

  return (
    <section className="card search-toolbar">
      <div className="search-toolbar-header">
        <div>
          <div className="search-toolbar-kicker">Queue Search</div>
          <div className="search-toolbar-description">
            Search subject, sender, recipient, domain, IP, URL, attachment name, or SHA-256.
          </div>
        </div>
        <div className="search-toolbar-meta">
          <span className="search-toolbar-results">
            {resultCount} {resultLabel}
          </span>
          {activeFilterCount > 0 ? (
            <span className="search-toolbar-active-count">
              {activeFilterCount} active filter{activeFilterCount === 1 ? "" : "s"}
            </span>
          ) : null}
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
        <div className="search-toolbar-filter-heading">Filters</div>
        <div className="search-toolbar-filters">
          <label className="search-toolbar-filter">
            <span>Status</span>
            <select
              className="select"
              value={status}
              onChange={(event) => onStatusChange((event.target.value as Report["status"] | "") || "")}
            >
              <option value="">All statuses</option>
              <option value="OPEN">Open</option>
              <option value="PHISHING">Phishing</option>
              <option value="BENIGN">Benign</option>
            </select>
          </label>

          <label className="search-toolbar-filter">
            <span>Classification</span>
            <select
              className="select"
              value={classification}
              onChange={(event) =>
                onClassificationChange((event.target.value as ClassificationCode | "") || "")
              }
            >
              <option value="">All classifications</option>
              {CLASSIFICATION_CODES.map((code) => (
                <option key={code} value={code}>
                  {code}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {activeFilterCount > 0 ? (
        <div className="search-toolbar-chip-row">
          {status ? (
            <button type="button" className="search-toolbar-chip" onClick={() => onStatusChange("")}>
              Status: {status}
              <span aria-hidden="true">×</span>
            </button>
          ) : null}
          {classification ? (
            <button
              type="button"
              className="search-toolbar-chip"
              onClick={() => onClassificationChange("")}
            >
              Classification: {classification}
              <span aria-hidden="true">×</span>
            </button>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

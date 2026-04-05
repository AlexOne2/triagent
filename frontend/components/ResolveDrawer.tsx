import { useEffect, useMemo, useState } from "react";

import {
  Attachment,
  CLASSIFICATION_CODES,
  ClassificationCode,
  fetchReportResolutions,
  FlaggedArtifact,
  Report,
  ReportResolutionEvent,
  resolveReport,
  ResolutionDisposition,
} from "../lib/api";
import { artifactKey, buildReportArtifacts } from "../lib/report-artifacts";

type ResolveDrawerProps = {
  open: boolean;
  report: Report;
  attachments?: Attachment[];
  onClose: () => void;
  onResolved: (report: Report) => void;
  preselectedArtifactKeys?: string[];
};

export default function ResolveDrawer({
  open,
  report,
  attachments = [],
  onClose,
  onResolved,
  preselectedArtifactKeys = [],
}: ResolveDrawerProps) {
  const [disposition, setDisposition] = useState<ResolutionDisposition>("MALICIOUS");
  const [classificationCode, setClassificationCode] = useState<ClassificationCode | "UNCLASSIFIED">("UNCLASSIFIED");
  const [note, setNote] = useState("");
  const [selectedArtifacts, setSelectedArtifacts] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ReportResolutionEvent[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const availableArtifacts = useMemo(() => buildReportArtifacts(report, attachments), [report, attachments]);

  useEffect(() => {
    if (!open) return;
    setDisposition("MALICIOUS");
    setClassificationCode(report.classification_code || "UNCLASSIFIED");
    setNote(report.resolution_note || "");
    setSelectedArtifacts(Array.from(new Set([
      ...(report.flagged_artifacts_json || []).map((artifact) => artifactKey(artifact)),
      ...preselectedArtifactKeys,
    ])));
    setError(null);
  }, [open, report, preselectedArtifactKeys]);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setHistoryLoading(true);
    fetchReportResolutions(report.id)
      .then((items) => {
        if (!active) return;
        setHistory(items);
      })
      .catch(() => {
        if (!active) return;
        setHistory([]);
      })
      .finally(() => {
        if (!active) return;
        setHistoryLoading(false);
      });
    return () => {
      active = false;
    };
  }, [open, report.id]);

  if (!open) {
    return null;
  }

  const chosenArtifacts = availableArtifacts.filter((artifact) =>
    selectedArtifacts.includes(artifactKey(artifact))
  );

  async function handleResolve() {
    if (disposition === "MALICIOUS" && classificationCode === "UNCLASSIFIED") {
      setError("Classification is required for malicious disposition.");
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const updated = await resolveReport(report.id, {
        disposition,
        classification_code: classificationCode === "UNCLASSIFIED" ? null : classificationCode,
        note: note.trim() || null,
        flagged_artifacts: chosenArtifacts,
      });
      onResolved(updated);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to resolve report.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="resolve-backdrop" onClick={onClose}>
      <aside className="resolve-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="resolve-drawer-header">
          <div>
            <p className="resolve-caption">Resolve</p>
            <h2>Resolution</h2>
          </div>
          <button className="resolve-close" type="button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="resolve-content">
          <section className="resolve-section">
            <h3>Disposition</h3>
            <div className="resolve-disposition">
              <button
                type="button"
                className={`resolve-pill ${disposition === "MALICIOUS" ? "active malicious" : ""}`.trim()}
                onClick={() => setDisposition("MALICIOUS")}
              >
                Malicious
              </button>
              <button
                type="button"
                className={`resolve-pill ${disposition === "SAFE" ? "active safe" : ""}`.trim()}
                onClick={() => setDisposition("SAFE")}
              >
                Safe
              </button>
            </div>
          </section>

          <section className="resolve-section">
            <h3>Flagged artifacts</h3>
            {availableArtifacts.length === 0 ? <p>No artifacts available.</p> : null}
            <div className="resolve-artifact-list">
              {availableArtifacts.map((artifact) => {
                const key = artifactKey(artifact);
                return (
                  <label key={key} className="resolve-artifact-item">
                    <input
                      type="checkbox"
                      checked={selectedArtifacts.includes(key)}
                      onChange={(event) => {
                        setSelectedArtifacts((current) =>
                          event.target.checked ? [...current, key] : current.filter((item) => item !== key)
                        );
                      }}
                    />
                    <span>{artifact.label || `${artifact.kind} - ${artifact.value}`}</span>
                  </label>
                );
              })}
            </div>
          </section>

          <section className="resolve-section">
            <h3>Classification code</h3>
            <select
              className="select"
              value={classificationCode}
              onChange={(event) =>
                setClassificationCode(event.target.value as ClassificationCode | "UNCLASSIFIED")
              }
            >
              <option value="UNCLASSIFIED">UNCLASSIFIED</option>
              {CLASSIFICATION_CODES.map((code) => (
                <option key={code} value={code}>
                  {code}
                </option>
              ))}
            </select>
          </section>

          <section className="resolve-section">
            <h3>Notes</h3>
            <textarea
              className="resolve-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Enter notes here..."
            />
          </section>

          <section className="resolve-section">
            <h3>Audit log</h3>
            {historyLoading ? <p>Loading history...</p> : null}
            {!historyLoading && history.length === 0 ? <p>No resolution history yet.</p> : null}
            {!historyLoading && history.length > 0 ? (
              <div className="resolve-artifact-list">
                {history.map((entry) => (
                  <div key={entry.id} className="meta-card">
                    <strong>{entry.action}</strong>{" "}
                    <span>
                      {entry.status_after}
                      {entry.disposition ? ` · ${entry.disposition}` : ""}
                      {entry.classification_code ? ` · ${entry.classification_code}` : ""}
                    </span>
                    <p>
                      {new Date(entry.created_at).toLocaleString()} · {entry.actor}
                    </p>
                    {entry.note ? <p>{entry.note}</p> : null}
                  </div>
                ))}
              </div>
            ) : null}
          </section>

          {error ? <p className="auth-error">{error}</p> : null}

          <button className="resolve-button" type="button" disabled={submitting} onClick={() => void handleResolve()}>
            {submitting ? "Resolving..." : "Resolve"}
          </button>
        </div>
      </aside>
    </div>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";

import {
  Attachment,
  CLASSIFICATION_CODES,
  ClassificationCode,
  fetchReportResolutions,
  FlaggedArtifact,
  generateReportAssistDraft,
  Report,
  ReportAssistDraft,
  ReportAssistConfidence,
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
  const [assistDraft, setAssistDraft] = useState<ReportAssistDraft | null>(null);
  const [assistLoading, setAssistLoading] = useState(false);
  const [assistError, setAssistError] = useState<string | null>(null);
  const userEditedRef = useRef(false);

  const availableArtifacts = useMemo(() => buildReportArtifacts(report, attachments), [report, attachments]);

  const baseSelectedArtifacts = () =>
    Array.from(
      new Set([
        ...(report.flagged_artifacts_json || []).map((artifact) => artifactKey(artifact)),
        ...preselectedArtifactKeys,
      ]),
    );

  function applyAssistDraft(draft: ReportAssistDraft) {
    setDisposition(draft.recommended_disposition);
    setClassificationCode(draft.recommended_classification_code || "UNCLASSIFIED");
    setNote(draft.recommended_note || "");
    setSelectedArtifacts(
      Array.from(
        new Set([...baseSelectedArtifacts(), ...draft.flagged_artifacts.map((artifact) => artifactKey(artifact))]),
      ),
    );
  }

  useEffect(() => {
    if (!open) return;
    userEditedRef.current = false;
    setDisposition("MALICIOUS");
    setClassificationCode(report.classification_code || "UNCLASSIFIED");
    setNote(report.resolution_note || "");
    setSelectedArtifacts(baseSelectedArtifacts());
    setError(null);
    setAssistDraft(null);
    setAssistError(null);
  }, [open, report, preselectedArtifactKeys]);

  useEffect(() => {
    if (!open) return;
    let active = true;
    setAssistLoading(true);
    setAssistError(null);
    generateReportAssistDraft(report.id)
      .then((draft) => {
        if (!active) return;
        setAssistDraft(draft);
        if (!userEditedRef.current) {
          applyAssistDraft(draft);
        }
      })
      .catch((err) => {
        if (!active) return;
        setAssistError(err instanceof Error ? err.message : "Failed to generate assist draft.");
      })
      .finally(() => {
        if (!active) return;
        setAssistLoading(false);
      });
    return () => {
      active = false;
    };
  }, [open, report.id]);

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

  const markEdited = () => {
    userEditedRef.current = true;
  };

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

  function confidenceTone(confidence: ReportAssistConfidence): "good" | "warn" | "neutral" {
    if (confidence === "high") return "good";
    if (confidence === "medium") return "warn";
    return "neutral";
  }

  function confidenceLabel(confidence: ReportAssistConfidence): string {
    return `${confidence} evidence support`;
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
            <div className="resolve-assist-head">
              <h3>Assist draft</h3>
            </div>
            {assistLoading ? <p>Generating assist draft...</p> : null}
            {assistError ? <p className="resolve-error">{assistError}</p> : null}
            {assistDraft ? (
              <div className="resolve-assist-card">
                <div className="resolve-assist-meta">
                  <span className={`url-badge url-badge-${confidenceTone(assistDraft.confidence)}`}>
                    {confidenceLabel(assistDraft.confidence)}
                  </span>
                  <span>
                    {assistDraft.recommended_disposition}
                    {assistDraft.recommended_classification_code
                      ? ` · ${assistDraft.recommended_classification_code}`
                      : ""}
                  </span>
                  <span>
                    {assistDraft.provider}
                    {assistDraft.model ? ` · ${assistDraft.model}` : ""}
                  </span>
                </div>
                <p className="resolve-assist-caption">
                  Confidence reflects how strongly the observed evidence supports this draft recommendation, not whether the report is automatically resolved.
                </p>
                <p className="resolve-assist-summary">{assistDraft.summary}</p>
                {assistDraft.reasons.length > 0 ? (
                  <div className="resolve-assist-block">
                    <strong>Why</strong>
                    <ul className="resolve-assist-list">
                      {assistDraft.reasons.map((reason, index) => (
                        <li key={`${reason}-${index}`}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {assistDraft.missing_evidence.length > 0 ? (
                  <div className="resolve-assist-block">
                    <strong>Missing evidence</strong>
                    <ul className="resolve-assist-list">
                      {assistDraft.missing_evidence.map((item, index) => (
                        <li key={`${item}-${index}`}>{item}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
                {assistDraft.review_warnings.length > 0 ? (
                  <div className="resolve-assist-block">
                    <strong>Review warnings</strong>
                    <ul className="resolve-assist-list">
                      {assistDraft.review_warnings.map((item, index) => (
                        <li key={`${item}-${index}`}>{item}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            ) : null}
          </section>

          <section className="resolve-section">
            <h3>Disposition</h3>
            <div className="resolve-disposition">
              <button
                type="button"
                className={`resolve-pill ${disposition === "MALICIOUS" ? "active malicious" : ""}`.trim()}
                onClick={() => {
                  markEdited();
                  setDisposition("MALICIOUS");
                }}
              >
                Malicious
              </button>
              <button
                type="button"
                className={`resolve-pill ${disposition === "SAFE" ? "active safe" : ""}`.trim()}
                onClick={() => {
                  markEdited();
                  setDisposition("SAFE");
                }}
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
                        markEdited();
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
              onChange={(event) => {
                markEdited();
                setClassificationCode(event.target.value as ClassificationCode | "UNCLASSIFIED");
              }}
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
              onChange={(event) => {
                markEdited();
                setNote(event.target.value);
              }}
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

          {error ? <p className="resolve-error">{error}</p> : null}

          <button className="resolve-button" type="button" disabled={submitting} onClick={() => void handleResolve()}>
            {submitting ? "Resolving..." : "Resolve"}
          </button>
        </div>
      </aside>
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";

import {
  CLASSIFICATION_CODES,
  ClassificationCode,
  fetchReportResolutions,
  FlaggedArtifact,
  Report,
  ReportResolutionEvent,
  resolveReport,
  ResolutionDisposition,
} from "../lib/api";

type ResolveDrawerProps = {
  open: boolean;
  report: Report;
  onClose: () => void;
  onResolved: (report: Report) => void;
};

function domainFromAddress(value?: string | null): string | null {
  if (!value) return null;
  const at = value.indexOf("@");
  if (at === -1 || at === value.length - 1) return null;
  return value.slice(at + 1).toLowerCase();
}

function domainFromUrl(value: string): string | null {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function buildArtifacts(report: Report): FlaggedArtifact[] {
  const items: FlaggedArtifact[] = [];
  const push = (artifact: FlaggedArtifact) => {
    if (!items.some((item) => item.kind === artifact.kind && item.value === artifact.value)) {
      items.push(artifact);
    }
  };

  if (report.from_addr) {
    push({
      kind: "FROM_ADDR",
      value: report.from_addr,
      label: `From email address - ${report.from_addr}`,
    });
    const fromDomain = domainFromAddress(report.from_addr);
    if (fromDomain) {
      push({
        kind: "FROM_DOMAIN",
        value: fromDomain,
        label: `From domain - ${fromDomain}`,
      });
    }
  }

  for (const replyTo of report.reply_to || []) {
    push({
      kind: "REPLY_TO",
      value: replyTo,
      label: `Reply-To - ${replyTo}`,
    });
  }

  if (report.return_path) {
    push({
      kind: "RETURN_PATH",
      value: report.return_path,
      label: `Return-Path email address - ${report.return_path}`,
    });
    const returnPathDomain = domainFromAddress(report.return_path);
    if (returnPathDomain) {
      push({
        kind: "RETURN_PATH_DOMAIN",
        value: returnPathDomain,
        label: `Return-Path domain - ${returnPathDomain}`,
      });
    }
  }

  if (report.originating_ip) {
    push({
      kind: "ORIGINATING_IP",
      value: report.originating_ip,
      label: `Originating IP - ${report.originating_ip}${report.originating_rdns ? ` (${report.originating_rdns})` : ""}`,
    });
  }

  for (const url of report.urls_json || []) {
    push({
      kind: "URL",
      value: url,
      label: `Message URL - ${url}`,
    });
    const urlDomain = domainFromUrl(url);
    if (urlDomain) {
      push({
        kind: "URL_DOMAIN",
        value: urlDomain,
        label: `Message URL domain - ${urlDomain}`,
      });
    }
  }

  return items;
}

export default function ResolveDrawer({ open, report, onClose, onResolved }: ResolveDrawerProps) {
  const [disposition, setDisposition] = useState<ResolutionDisposition>("MALICIOUS");
  const [classificationCode, setClassificationCode] = useState<ClassificationCode | "UNCLASSIFIED">("UNCLASSIFIED");
  const [note, setNote] = useState("");
  const [selectedArtifacts, setSelectedArtifacts] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<ReportResolutionEvent[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const availableArtifacts = useMemo(() => buildArtifacts(report), [report]);

  useEffect(() => {
    if (!open) return;
    setDisposition("MALICIOUS");
    setClassificationCode(report.classification_code || "UNCLASSIFIED");
    setNote(report.resolution_note || "");
    setSelectedArtifacts(
      (report.flagged_artifacts_json || []).map((artifact) => `${artifact.kind}::${artifact.value}`)
    );
    setError(null);
  }, [open, report]);

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
    selectedArtifacts.includes(`${artifact.kind}::${artifact.value}`)
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
                const key = `${artifact.kind}::${artifact.value}`;
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

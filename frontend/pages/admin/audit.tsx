import { FormEvent, useEffect, useMemo, useState } from "react";
import AdminNav from "../../components/AdminNav";
import {
  AuditActorType,
  AuditEvent,
  AuditExportRecord,
  AuditVerifyResult,
  downloadAuditNdjson,
  fetchAuditEvents,
  fetchAuditExports,
  verifyAuditChain,
} from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

const ACTOR_TYPES: AuditActorType[] = ["USER", "API_KEY", "SYSTEM", "LEGACY"];

export default function AdminAuditPage() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("audit.read");
  const canVerify = hasPermission("audit.verify");
  const canExport = hasPermission("audit.export");

  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [exportRows, setExportRows] = useState<AuditExportRecord[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [nextCursor, setNextCursor] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingExports, setLoadingExports] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);

  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [actorType, setActorType] = useState("");
  const [targetType, setTargetType] = useState("");
  const [targetId, setTargetId] = useState("");
  const [requestId, setRequestId] = useState("");

  const queryParams = useMemo(
    () => ({
      start: start || undefined,
      end: end || undefined,
      action: action || undefined,
      outcome: outcome || undefined,
      actor_type: (actorType || undefined) as AuditActorType | undefined,
      target_type: targetType || undefined,
      target_id: targetId || undefined,
      request_id: requestId || undefined,
      limit: 100,
    }),
    [start, end, action, outcome, actorType, targetType, targetId, requestId]
  );

  const loadEvents = async (cursor?: number | null, append = false) => {
    if (!canRead) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetchAuditEvents({
        ...queryParams,
        cursor: cursor || undefined,
      });
      setEvents((current) => (append ? [...current, ...response.items] : response.items));
      setNextCursor(response.next_cursor || null);
      if (!append) {
        setSelectedEvent(response.items[0] || null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load audit events");
    } finally {
      setLoading(false);
    }
  };

  const loadExports = async () => {
    if (!canRead) return;
    setLoadingExports(true);
    try {
      const rows = await fetchAuditExports();
      setExportRows(rows);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load audit exports");
    } finally {
      setLoadingExports(false);
    }
  };

  useEffect(() => {
    void loadEvents();
    void loadExports();
  }, [canRead]);

  const onFilter = async (event: FormEvent) => {
    event.preventDefault();
    await loadEvents(undefined, false);
  };

  const onVerify = async () => {
    if (!canVerify || verifyBusy) return;
    setVerifyBusy(true);
    setError(null);
    try {
      const result = await verifyAuditChain({ start: start || undefined, end: end || undefined });
      setVerifyResult(result);
      await loadEvents(undefined, false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to verify chain");
    } finally {
      setVerifyBusy(false);
    }
  };

  const onExport = async () => {
    if (!canExport || exportBusy || !start || !end) return;
    setExportBusy(true);
    setError(null);
    try {
      const blob = await downloadAuditNdjson({ start, end });
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = `audit-${start}-${end}.ndjson`;
      link.click();
      URL.revokeObjectURL(objectUrl);
      await loadExports();
      await loadEvents(undefined, false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export NDJSON");
    } finally {
      setExportBusy(false);
    }
  };

  if (!canRead) {
    return (
      <main className="full">
        <h1>Admin - Audit</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  return (
    <main className="full">
      <header>
        <div>
          <h1>Admin - Audit</h1>
          <p>Search, verify, and export immutable audit trails.</p>
        </div>
      </header>
      <AdminNav />

      {error ? <p className="auth-error">{error}</p> : null}

      <section className="card" style={{ marginBottom: 16 }}>
        <h2>Filters</h2>
        <form className="admin-form" onSubmit={onFilter}>
          <input className="input" placeholder="Start ISO (2026-02-01T00:00:00Z)" value={start} onChange={(event) => setStart(event.target.value)} />
          <input className="input" placeholder="End ISO (2026-02-20T23:59:59Z)" value={end} onChange={(event) => setEnd(event.target.value)} />
          <input className="input" placeholder="Action (AUTH_LOGIN_SUCCESS)" value={action} onChange={(event) => setAction(event.target.value)} />
          <input className="input" placeholder="Outcome (SUCCESS/FAILURE)" value={outcome} onChange={(event) => setOutcome(event.target.value)} />
          <select className="select" value={actorType} onChange={(event) => setActorType(event.target.value)}>
            <option value="">Any actor type</option>
            {ACTOR_TYPES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
          <input className="input" placeholder="Target type" value={targetType} onChange={(event) => setTargetType(event.target.value)} />
          <input className="input" placeholder="Target id" value={targetId} onChange={(event) => setTargetId(event.target.value)} />
          <input className="input" placeholder="Request ID" value={requestId} onChange={(event) => setRequestId(event.target.value)} />
          <button className="resolve-button" type="submit" disabled={loading}>
            {loading ? "Loading..." : "Search"}
          </button>
          {canVerify ? (
            <button className="tab" type="button" onClick={() => void onVerify()} disabled={verifyBusy}>
              {verifyBusy ? "Verifying..." : "Verify Chain"}
            </button>
          ) : null}
          {canExport ? (
            <button className="tab" type="button" onClick={() => void onExport()} disabled={exportBusy || !start || !end}>
              {exportBusy ? "Exporting..." : "Export NDJSON"}
            </button>
          ) : null}
        </form>

        {verifyResult ? (
          <div className={`audit-verify ${verifyResult.valid ? "ok" : "bad"}`}>
            <strong>{verifyResult.valid ? "Chain valid" : "Chain invalid"}</strong>
            <span>Checked: {verifyResult.checked_count}</span>
            {verifyResult.first_invalid_event_id ? <span>First invalid event: {verifyResult.first_invalid_event_id}</span> : null}
          </div>
        ) : null}
      </section>

      <section className="card" style={{ marginBottom: 16 }}>
        <h2>Audit Events</h2>
        {loading ? <p>Loading events...</p> : null}
        {!loading && events.length === 0 ? <p>No events found for the selected criteria.</p> : null}
        {events.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Request ID</th>
              </tr>
            </thead>
            <tbody>
              {events.map((item) => (
                <tr key={item.id} onClick={() => setSelectedEvent(item)} style={{ cursor: "pointer" }}>
                  <td>{item.id}</td>
                  <td>{new Date(item.created_at).toLocaleString()}</td>
                  <td>{item.action}</td>
                  <td>{item.outcome}</td>
                  <td>{item.actor_type}</td>
                  <td>{item.target_type ? `${item.target_type}:${item.target_id || "-"}` : "-"}</td>
                  <td>{item.request_id || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        {nextCursor ? (
          <div style={{ marginTop: 10 }}>
            <button className="tab" type="button" onClick={() => void loadEvents(nextCursor, true)} disabled={loading}>
              Load more
            </button>
          </div>
        ) : null}
      </section>

      {selectedEvent ? (
        <section className="card" style={{ marginBottom: 16 }}>
          <h2>Event Detail</h2>
          <div className="kv">
            <label>Event UUID</label>
            <div className="audit-mono">{selectedEvent.event_uuid}</div>
            <label>Prev Hash</label>
            <div className="audit-mono">{selectedEvent.prev_hash}</div>
            <label>Event Hash</label>
            <div className="audit-mono">{selectedEvent.event_hash}</div>
            <label>Correlation ID</label>
            <div>{selectedEvent.correlation_id || "-"}</div>
            <label>Metadata</label>
            <pre className="report-body">{JSON.stringify(selectedEvent.metadata_json || {}, null, 2)}</pre>
          </div>
        </section>
      ) : null}

      <section className="card">
        <h2>Recorded Exports</h2>
        {loadingExports ? <p>Loading exports...</p> : null}
        {!loadingExports && exportRows.length === 0 ? <p>No export manifests recorded yet.</p> : null}
        {exportRows.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Range</th>
                <th>Events</th>
                <th>Root Hash</th>
                <th>Storage URI</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {exportRows.map((item) => (
                <tr key={item.id}>
                  <td>{item.id}</td>
                  <td>
                    {new Date(item.range_start).toLocaleString()} - {new Date(item.range_end).toLocaleString()}
                  </td>
                  <td>{item.event_count}</td>
                  <td className="audit-mono">{item.root_hash}</td>
                  <td className="audit-mono">{item.storage_uri}</td>
                  <td>{new Date(item.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </main>
  );
}

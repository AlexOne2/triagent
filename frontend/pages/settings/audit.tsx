import { FormEvent, useEffect, useMemo, useState } from "react";
import SettingsLayout from "../../components/SettingsLayout";
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

function formatAuditActor(item: AuditEvent) {
  if (item.actor_type === "USER") {
    return item.actor_user_id ? `user:${item.actor_user_id}` : "user";
  }
  if (item.actor_type === "API_KEY") {
    return item.actor_api_key_id ? `api-key:${item.actor_api_key_id}` : "api-key";
  }
  if (item.actor_type === "LEGACY") {
    return "legacy";
  }
  return "system";
}

function formatAuditTarget(item: Pick<AuditEvent, "target_type" | "target_id">) {
  if (!item.target_type && !item.target_id) return "-";
  if (!item.target_type) return item.target_id || "-";
  if (!item.target_id) return item.target_type;
  return `${item.target_type}:${item.target_id}`;
}

export default function SettingsAuditPage() {
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
        <h1>Settings - Audit Log</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  return (
    <SettingsLayout title="Audit Log" description="Search, verify, and export immutable audit trails.">
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
                  <td>{formatAuditActor(item)}</td>
                  <td>{formatAuditTarget(item)}</td>
                  <td>{item.request_id || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}

        {nextCursor ? (
          <button className="tab" type="button" onClick={() => void loadEvents(nextCursor, true)} disabled={loading}>
            Load more
          </button>
        ) : null}
      </section>

      <section className="audit-grid">
        <section className="card">
          <h2>Selected Event</h2>
          {selectedEvent ? (
            <dl className="audit-detail">
              <dt>ID</dt>
              <dd>{selectedEvent.id}</dd>
              <dt>Timestamp</dt>
              <dd>{new Date(selectedEvent.created_at).toLocaleString()}</dd>
              <dt>Action</dt>
              <dd>{selectedEvent.action}</dd>
              <dt>Outcome</dt>
              <dd>{selectedEvent.outcome}</dd>
              <dt>Actor Type</dt>
              <dd>{selectedEvent.actor_type}</dd>
              <dt>Actor</dt>
              <dd>{formatAuditActor(selectedEvent)}</dd>
              <dt>Target</dt>
              <dd>{formatAuditTarget(selectedEvent)}</dd>
              <dt>Request ID</dt>
              <dd>{selectedEvent.request_id || "-"}</dd>
              <dt>Event UUID</dt>
              <dd>{selectedEvent.event_uuid}</dd>
              <dt>Prev Hash</dt>
              <dd>{selectedEvent.prev_hash || "-"}</dd>
              <dt>Event Hash</dt>
              <dd>{selectedEvent.event_hash}</dd>
              <dt>Payload</dt>
              <dd>
                <pre>{JSON.stringify(selectedEvent.metadata_json || {}, null, 2)}</pre>
              </dd>
            </dl>
          ) : (
            <p>Select an event to inspect its payload.</p>
          )}
        </section>

        <section className="card">
          <h2>Export History</h2>
          {loadingExports ? <p>Loading exports...</p> : null}
          {!loadingExports && exportRows.length === 0 ? <p>No exports recorded yet.</p> : null}
          {exportRows.length > 0 ? (
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Created</th>
                  <th>Actor</th>
                  <th>Range Start</th>
                  <th>Range End</th>
                  <th>Object Key</th>
                </tr>
              </thead>
              <tbody>
                {exportRows.map((row) => (
                  <tr key={row.id}>
                    <td>{row.id}</td>
                    <td>{new Date(row.created_at).toLocaleString()}</td>
                    <td>{row.created_by}</td>
                    <td>{row.range_start}</td>
                    <td>{row.range_end}</td>
                    <td>{row.storage_uri}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </section>
      </section>
    </SettingsLayout>
  );
}

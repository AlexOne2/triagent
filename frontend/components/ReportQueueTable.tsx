import Link from "next/link";
import { Report } from "../lib/api";
import { formatTriageReasonCode, getTriageBucketMeta } from "../lib/triage";

type ReportQueueTableProps = {
  reports: Report[];
  loading: boolean;
  emptyMessage: string;
};

function statusClass(status: Report["status"]) {
  if (status === "PHISHING") return "badge phishing";
  if (status === "BENIGN") return "badge";
  return "badge open";
}

function statusLabel(status: Report["status"]) {
  if (status === "PHISHING") return "Malicious";
  if (status === "BENIGN") return "Safe";
  return "Open";
}

function formatRecipientSummary(report: Report) {
  const recipients = report.to_addrs?.filter(Boolean) || [];
  if (recipients.length === 0) {
    return null;
  }
  if (recipients.length === 1) {
    return `To ${recipients[0]}`;
  }
  return `To ${recipients[0]} +${recipients.length - 1}`;
}

function formatSenderSummary(report: Report) {
  const sender = report.from_addr || "Unknown sender";
  return `From ${sender}`;
}

function formatReportTimestamp(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed);
}

export default function ReportQueueTable({ reports, loading, emptyMessage }: ReportQueueTableProps) {
  if (loading) {
    return <p>Loading...</p>;
  }

  if (reports.length === 0) {
    return <p>{emptyMessage}</p>;
  }

  return (
    <table className="table queue-table">
      <thead>
        <tr>
          <th>Message</th>
          <th>Signals</th>
          <th>Queue</th>
          <th>Resolution</th>
          <th>Date</th>
        </tr>
      </thead>
      <tbody>
        {reports.map((report) => {
          const triage = report.triage_assessment;
          const meta = triage ? getTriageBucketMeta(triage.bucket) : null;
          const reasonCodes = triage?.reason_codes?.slice(0, 3) || [];
          const remainingReasonCount = Math.max((triage?.reason_codes?.length || 0) - reasonCodes.length, 0);
          const recipientSummary = formatRecipientSummary(report);
          return (
            <tr key={report.id}>
              <td className="queue-message-cell">
                <Link href={`/reports/${report.id}`} className="queue-message-link">
                  {report.subject || "(no subject)"}
                </Link>
                <div className="queue-message-meta">
                  <span>{formatSenderSummary(report)}</span>
                  {recipientSummary ? <span>{recipientSummary}</span> : null}
                </div>
              </td>
              <td className="queue-signal-cell">
                {reasonCodes.length > 0 ? (
                  <div className="queue-signal-list">
                    {reasonCodes.map((code) => (
                      <span key={`${report.id}-${code}`} className="queue-signal-chip">
                        {formatTriageReasonCode(code)}
                      </span>
                    ))}
                    {remainingReasonCount > 0 ? (
                      <span className="queue-signal-chip queue-signal-chip-muted">+{remainingReasonCount}</span>
                    ) : null}
                  </div>
                ) : (
                  <span className="queue-muted-copy">Limited context</span>
                )}
              </td>
              <td className="queue-lane-cell">
                {meta ? (
                  <span
                    className={`triage-inline-badge triage-inline-badge-${meta.tone}`.trim()}
                    title={triage?.summary || meta.description}
                  >
                    {meta.shortLabel}
                  </span>
                ) : (
                  <span className="queue-muted-copy">Unscored</span>
                )}
              </td>
              <td className="queue-status-cell">
                <span className={statusClass(report.status)}>{statusLabel(report.status)}</span>
                <div className="queue-status-meta">
                  {report.classification_code || (report.status === "OPEN" ? "Unclassified" : "No classification")}
                </div>
              </td>
              <td className="queue-date-cell" title={new Date(report.created_at).toLocaleString()}>
                {formatReportTimestamp(report.created_at)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

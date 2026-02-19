export const CLASSIFICATION_CODES = [
  "CRED_HARV",
  "DRIVE_BY",
  "RECON",
  "REPLY_SOLICIT",
  "SPOOF",
  "MAL_ATTACH",
  "MAL_URL",
  "MAL_WEBAPP",
  "MALWARE",
  "COMPRO_SEND",
  "THREAD_HIJACK",
  "FIN_FRAUD",
  "WEBMAIL",
  "WHALE",
  "VOLUME",
  "SPEAR",
  "POLY",
  "IMPER",
  "GOV_IMPER",
  "3P_IMPER",
  "T3P_IMPER",
  "VIP_IMPER",
] as const;

export type ClassificationCode = (typeof CLASSIFICATION_CODES)[number];
export type ResolutionDisposition = "MALICIOUS" | "SAFE";
export type ArtifactKind =
  | "FROM_ADDR"
  | "FROM_DOMAIN"
  | "REPLY_TO"
  | "RETURN_PATH"
  | "RETURN_PATH_DOMAIN"
  | "ORIGINATING_IP"
  | "URL"
  | "URL_DOMAIN";

export type FlaggedArtifact = {
  kind: ArtifactKind;
  value: string;
  label?: string | null;
};

export type ReportResolutionEvent = {
  id: number;
  action: "RESOLVE" | "REOPEN";
  disposition?: ResolutionDisposition | null;
  status_after: "OPEN" | "BENIGN" | "PHISHING";
  classification_code?: ClassificationCode | null;
  note?: string | null;
  flagged_artifacts: FlaggedArtifact[];
  actor: string;
  created_at: string;
};

export type Report = {
  id: number;
  message_id?: string | null;
  received_at?: string | null;
  subject?: string | null;
  from_addr?: string | null;
  from_display_name?: string | null;
  to_addrs?: string[] | null;
  cc_addrs?: string[] | null;
  date?: string | null;
  body_text?: string | null;
  body_html?: string | null;
  headers_json?: Record<string, unknown> | null;
  urls_json?: string[] | null;
  reporter_hash?: string | null;
  mailbox_domain?: string | null;
  raw_source?: string | null;
  sender?: string | null;
  reply_to?: string[] | null;
  in_reply_to?: string | null;
  return_path?: string | null;
  originating_ip?: string | null;
  originating_rdns?: string | null;
  risk_score: number;
  status: "OPEN" | "BENIGN" | "PHISHING";
  classification_code?: ClassificationCode | null;
  resolution_note?: string | null;
  flagged_artifacts_json?: FlaggedArtifact[] | null;
  resolved_at?: string | null;
  last_resolved_by?: string | null;
  ingest_source?: "UPLOAD" | "AUTO";
  created_at: string;
};

export type ReportStats = {
  total: number;
  open: number;
  benign: number;
  phishing: number;
};

export type DashboardOverview = {
  kpis: {
    total_ingested: number;
    resolved_total: number;
    resolved_malicious: number;
    resolved_safe: number;
  };
  resolutions_timeseries: Array<{
    date: string;
    resolved_total: number;
    resolved_malicious: number;
    resolved_safe: number;
  }>;
  malicious_safe: {
    malicious: number;
    safe: number;
  };
  classifications: Array<{
    code: string;
    count: number;
  }>;
  top_to_addresses: Array<{
    rank: number;
    email: string;
    count: number;
  }>;
  top_from_addresses: Array<{
    rank: number;
    email: string;
    count: number;
  }>;
};

const BASE_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
const API_USERNAME = process.env.NEXT_PUBLIC_API_USERNAME;
const API_PASSWORD = process.env.NEXT_PUBLIC_API_PASSWORD;

function basicAuthHeader(): string | undefined {
  if (!API_USERNAME || !API_PASSWORD) return undefined;
  const token = `${API_USERNAME}:${API_PASSWORD}`;
  if (typeof window === "undefined") {
    return `Basic ${Buffer.from(token).toString("base64")}`;
  }
  return `Basic ${btoa(token)}`;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const authHeader = basicAuthHeader();
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(authHeader ? { Authorization: authHeader } : {})
    },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchReports(
  query?: string,
  status?: Report["status"],
  source?: Report["ingest_source"]
): Promise<Report[]> {
  const params = new URLSearchParams();
  if (query) params.set("q", query);
  if (status) params.set("status", status);
  if (source) params.set("source", source);
  return request<Report[]>(`/api/reports?${params.toString()}`);
}

export async function fetchReport(id: string | number): Promise<Report> {
  return request<Report>(`/api/reports/${id}`);
}

export async function updateReport(
  id: number,
  payload: { status?: Report["status"]; classification_code?: ClassificationCode | null }
): Promise<Report> {
  return request<Report>(`/api/reports/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function resolveReport(
  id: number,
  payload: {
    disposition: ResolutionDisposition;
    classification_code?: ClassificationCode | null;
    note?: string | null;
    flagged_artifacts?: FlaggedArtifact[];
  }
): Promise<Report> {
  return request<Report>(`/api/reports/${id}/resolve`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function reopenReport(id: number): Promise<Report> {
  return request<Report>(`/api/reports/${id}/reopen`, {
    method: "POST",
  });
}

export async function fetchReportResolutions(id: number): Promise<ReportResolutionEvent[]> {
  return request<ReportResolutionEvent[]>(`/api/reports/${id}/resolutions`);
}

export async function uploadEml(file: File): Promise<{ report_id: number; risk_score: number }> {
  const authHeader = basicAuthHeader();
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE_URL}/api/report-eml`, {
    method: "POST",
    headers: authHeader ? { Authorization: authHeader } : undefined,
    body: form,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Upload failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchReportStats(): Promise<ReportStats> {
  return request<ReportStats>("/api/reports/stats");
}

export async function fetchDashboardOverview(params: {
  start: string;
  end: string;
  tz?: string;
}): Promise<DashboardOverview> {
  const search = new URLSearchParams({
    start: params.start,
    end: params.end,
  });
  if (params.tz) {
    search.set("tz", params.tz);
  }
  return request<DashboardOverview>(`/api/dashboard/overview?${search.toString()}`);
}

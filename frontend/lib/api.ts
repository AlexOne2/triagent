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
  ingest_source?: "UPLOAD" | "AUTO";
  created_at: string;
};

export type ReportStats = {
  total: number;
  open: number;
  benign: number;
  phishing: number;
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

export async function updateReportStatus(id: number, status: Report["status"]): Promise<Report> {
  return request<Report>(`/api/reports/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
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

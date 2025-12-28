export type Cluster = {
  id: number;
  fingerprint: string;
  subject_norm: string;
  from_domain: string | null;
  first_seen: string;
  last_seen: string;
  report_count: number;
  risk_score: number;
  status: "OPEN" | "BENIGN" | "PHISHING";
  created_at: string;
};

export type Report = {
  id: number;
  cluster_id: number;
  message_id?: string | null;
  received_at?: string | null;
  subject?: string | null;
  from_addr?: string | null;
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
  created_at: string;
};

export type ClusterDetail = Cluster & { reports: Report[] };

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

export async function fetchClusters(query?: string): Promise<Cluster[]> {
  const params = new URLSearchParams();
  if (query) params.set("q", query);
  return request<Cluster[]>(`/api/clusters?${params.toString()}`);
}

export async function fetchCluster(id: string | number): Promise<ClusterDetail> {
  return request<ClusterDetail>(`/api/clusters/${id}`);
}

export async function updateClusterStatus(id: number, status: Cluster["status"]): Promise<Cluster> {
  return request<Cluster>(`/api/clusters/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

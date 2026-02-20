import { getAccessToken } from "./auth-storage";

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

export type AuthUser = {
  id: number;
  username: string;
  email?: string | null;
  is_active: boolean;
  must_change_password: boolean;
  last_login_at?: string | null;
  created_at: string;
  updated_at: string;
};

export type AuthLoginResponse = {
  access_token: string;
  token_type: "bearer";
  expires_at: string;
  user: AuthUser;
  permissions: string[];
  roles: string[];
};

export type AuthMeResponse = {
  user: AuthUser;
  roles: string[];
  permissions: string[];
};

export type PermissionOut = {
  id: number;
  key: string;
  description?: string | null;
  created_at: string;
};

export type AdminRoleOut = {
  id: number;
  key: string;
  name: string;
  description?: string | null;
  is_system: boolean;
  permissions: string[];
  created_at: string;
};

export type AdminUserOut = {
  id: number;
  username: string;
  email?: string | null;
  is_active: boolean;
  must_change_password: boolean;
  failed_login_attempts: number;
  locked_until?: string | null;
  last_login_at?: string | null;
  role_keys: string[];
  created_at: string;
  updated_at: string;
};

export type AdminApiKeyOut = {
  id: number;
  name: string;
  key_prefix: string;
  role_key: string;
  created_by_user_id?: number | null;
  expires_at?: string | null;
  revoked_at?: string | null;
  last_used_at?: string | null;
  created_at: string;
  api_key?: string | null;
};

export type AuditActorType = "USER" | "API_KEY" | "SYSTEM" | "LEGACY";

export type AuditEvent = {
  id: number;
  event_uuid: string;
  actor_type: AuditActorType;
  actor_user_id?: number | null;
  actor_api_key_id?: number | null;
  action: string;
  target_type?: string | null;
  target_id?: string | null;
  outcome: string;
  request_id?: string | null;
  correlation_id?: string | null;
  schema_version: number;
  metadata_json?: Record<string, unknown> | null;
  ip?: string | null;
  user_agent?: string | null;
  prev_hash: string;
  event_hash: string;
  created_at: string;
};

export type AuditEventList = {
  items: AuditEvent[];
  next_cursor?: number | null;
};

export type AuditVerifyResult = {
  valid: boolean;
  checked_count: number;
  first_invalid_event_id?: number | null;
  expected_hash?: string | null;
  actual_hash?: string | null;
  range_start?: string | null;
  range_end?: string | null;
};

export type AuditExportRecord = {
  id: number;
  range_start: string;
  range_end: string;
  event_count: number;
  root_hash: string;
  manifest_json: Record<string, unknown>;
  storage_uri: string;
  created_by: string;
  created_at: string;
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
  actor_user_id?: number | null;
  actor_api_key_id?: number | null;
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

export type Attachment = {
  id: number;
  report_id: number;
  filename?: string | null;
  content_type?: string | null;
  size_bytes?: number | null;
  sha256?: string | null;
  s3_key?: string | null;
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

let unauthorizedHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

async function request<T>(
  path: string,
  options?: RequestInit,
  config: { auth?: boolean; expectJson?: boolean } = {}
): Promise<T> {
  const requiresAuth = config.auth ?? true;
  const token = requiresAuth ? getAccessToken() : null;

  const headers: Record<string, string> = {
    ...(options?.headers as Record<string, string> | undefined),
  };

  if (!headers["Content-Type"] && options?.body && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401 && requiresAuth && unauthorizedHandler) {
    unauthorizedHandler();
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }

  if (config.expectJson === false || res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

export async function authLogin(payload: { username: string; password: string }): Promise<AuthLoginResponse> {
  return request<AuthLoginResponse>(
    "/api/auth/login",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    { auth: false }
  );
}

export async function authMe(): Promise<AuthMeResponse> {
  return request<AuthMeResponse>("/api/auth/me");
}

export async function authLogout(): Promise<void> {
  await request<void>(
    "/api/auth/logout",
    {
      method: "POST",
    },
    { expectJson: false }
  );
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
  const token = getAccessToken();
  const form = new FormData();
  form.append("file", file);

  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}/api/report-eml`, {
    method: "POST",
    headers,
    body: form,
  });

  if (res.status === 401 && unauthorizedHandler) {
    unauthorizedHandler();
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Upload failed: ${res.status}`);
  }
  return res.json();
}

export async function uploadMsg(file: File): Promise<{ report_id: number; risk_score: number }> {
  const token = getAccessToken();
  const form = new FormData();
  form.append("file", file);

  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}/api/report-msg`, {
    method: "POST",
    headers,
    body: form,
  });

  if (res.status === 401 && unauthorizedHandler) {
    unauthorizedHandler();
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Upload failed: ${res.status}`);
  }
  return res.json();
}

export async function fetchReportAttachments(reportId: number): Promise<Attachment[]> {
  return request<Attachment[]>(`/api/reports/${reportId}/attachments`);
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

export async function fetchRoles(): Promise<AdminRoleOut[]> {
  return request<AdminRoleOut[]>("/api/admin/roles");
}

export async function fetchPermissions(): Promise<PermissionOut[]> {
  return request<PermissionOut[]>("/api/admin/permissions");
}

export async function fetchUsers(): Promise<AdminUserOut[]> {
  return request<AdminUserOut[]>("/api/admin/users");
}

export async function createUser(payload: {
  username: string;
  email?: string | null;
  password: string;
  role_keys: string[];
  is_active: boolean;
}): Promise<AdminUserOut> {
  return request<AdminUserOut>("/api/admin/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateUser(
  userId: number,
  payload: { email?: string | null; password?: string | null; is_active?: boolean }
): Promise<AdminUserOut> {
  return request<AdminUserOut>(`/api/admin/users/${userId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function replaceUserRoles(userId: number, roleKeys: string[]): Promise<AdminUserOut> {
  return request<AdminUserOut>(`/api/admin/users/${userId}/roles`, {
    method: "PUT",
    body: JSON.stringify({ role_keys: roleKeys }),
  });
}

export async function fetchApiKeys(): Promise<AdminApiKeyOut[]> {
  return request<AdminApiKeyOut[]>("/api/admin/api-keys");
}

export async function createApiKey(payload: {
  name: string;
  role_key: "INGESTOR";
  expires_at?: string | null;
}): Promise<AdminApiKeyOut> {
  return request<AdminApiKeyOut>("/api/admin/api-keys", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function revokeApiKey(id: number): Promise<AdminApiKeyOut> {
  return request<AdminApiKeyOut>(`/api/admin/api-keys/${id}/revoke`, {
    method: "POST",
  });
}

export async function fetchAuditEvents(params?: {
  start?: string;
  end?: string;
  action?: string;
  outcome?: string;
  actor_type?: AuditActorType;
  actor_user_id?: number;
  target_type?: string;
  target_id?: string;
  request_id?: string;
  limit?: number;
  cursor?: number;
}): Promise<AuditEventList> {
  const search = new URLSearchParams();
  if (params?.start) search.set("start", params.start);
  if (params?.end) search.set("end", params.end);
  if (params?.action) search.set("action", params.action);
  if (params?.outcome) search.set("outcome", params.outcome);
  if (params?.actor_type) search.set("actor_type", params.actor_type);
  if (params?.actor_user_id) search.set("actor_user_id", String(params.actor_user_id));
  if (params?.target_type) search.set("target_type", params.target_type);
  if (params?.target_id) search.set("target_id", params.target_id);
  if (params?.request_id) search.set("request_id", params.request_id);
  if (params?.limit) search.set("limit", String(params.limit));
  if (params?.cursor) search.set("cursor", String(params.cursor));
  const suffix = search.toString();
  return request<AuditEventList>(suffix ? `/api/admin/audit/events?${suffix}` : "/api/admin/audit/events");
}

export async function fetchAuditEvent(eventId: number): Promise<AuditEvent> {
  return request<AuditEvent>(`/api/admin/audit/events/${eventId}`);
}

export async function verifyAuditChain(params?: { start?: string; end?: string }): Promise<AuditVerifyResult> {
  const search = new URLSearchParams();
  if (params?.start) search.set("start", params.start);
  if (params?.end) search.set("end", params.end);
  const suffix = search.toString();
  return request<AuditVerifyResult>(suffix ? `/api/admin/audit/verify?${suffix}` : "/api/admin/audit/verify");
}

export async function fetchAuditExports(limit = 100): Promise<AuditExportRecord[]> {
  return request<AuditExportRecord[]>(`/api/admin/audit/exports?limit=${limit}`);
}

export async function downloadAuditNdjson(params: { start: string; end: string }): Promise<Blob> {
  const token = getAccessToken();
  const search = new URLSearchParams({ start: params.start, end: params.end });
  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}/api/admin/audit/export.ndjson?${search.toString()}`, {
    method: "GET",
    headers,
  });

  if (res.status === 401 && unauthorizedHandler) {
    unauthorizedHandler();
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Export failed: ${res.status}`);
  }
  return res.blob();
}

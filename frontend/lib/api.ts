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
export type AuthStatus =
  | "pass"
  | "fail"
  | "softfail"
  | "neutral"
  | "temperror"
  | "permerror"
  | "none"
  | "unknown";
export type ArtifactKind =
  | "FROM_ADDR"
  | "FROM_DOMAIN"
  | "REPLY_TO"
  | "RETURN_PATH"
  | "RETURN_PATH_DOMAIN"
  | "ORIGINATING_IP"
  | "URL"
  | "URL_DOMAIN"
  | "ATTACHMENT_NAME"
  | "ATTACHMENT_SHA256";

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

export type ReportAuthDkimSignature = {
  result: AuthStatus;
  signing_domain?: string | null;
  identity?: string | null;
  selector?: string | null;
  algorithm?: string | null;
  canonicalization?: string | null;
  raw?: string | null;
};

export type ReportAuthSummary = {
  overview: {
    spf: AuthStatus;
    dkim: AuthStatus;
    dmarc: AuthStatus;
    arc: AuthStatus;
  };
  spf: {
    result: AuthStatus;
    source_header?: string | null;
    authserv_id?: string | null;
    receiver?: string | null;
    smtp_mailfrom?: string | null;
    smtp_helo?: string | null;
    return_path_domain?: string | null;
    originating_ip?: string | null;
    originating_rdns?: string | null;
    dns_record?: string | null;
    raw?: string | null;
  };
  dkim: {
    result: AuthStatus;
    signature_count: number;
    signatures: ReportAuthDkimSignature[];
  };
  dmarc: {
    result: AuthStatus;
    header_from?: string | null;
    aligned_from_domain?: string | null;
    aligned_mailfrom_domain?: string | null;
    policy?: string | null;
    dns_record?: string | null;
    raw?: string | null;
  };
  arc: {
    result: AuthStatus;
    instance?: string | null;
    seal_result: AuthStatus;
    message_signature_result: AuthStatus;
    auth_results?: string | null;
    seal?: string | null;
    message_signature?: string | null;
    raw?: string | null;
  };
  raw_headers: {
    authentication_results?: string | null;
    received_spf?: string | null;
    arc_authentication_results?: string | null;
    arc_seal?: string | null;
    arc_message_signature?: string | null;
  };
};

export type CampaignAssignmentMethod = "AUTO" | "MANUAL";
export type UrlResolutionStatus =
  | "resolved"
  | "no_redirect"
  | "max_hops_exceeded"
  | "loop_detected"
  | "error"
  | "disabled"
  | "unsupported_scheme"
  | "skipped_limit";

export type UrlRedirectHop = {
  index: number;
  url: string;
  domain?: string | null;
  status_code?: number | null;
  location?: string | null;
};

export type UrlAnalysis = {
  original_url: string;
  normalized_url: string;
  initial_domain?: string | null;
  final_url?: string | null;
  final_domain?: string | null;
  redirect_count: number;
  is_shortener: boolean;
  used_redirector: boolean;
  domain_changed: boolean;
  suspicious_redirect: boolean;
  resolution_status: UrlResolutionStatus;
  resolution_error?: string | null;
  redirect_chain: UrlRedirectHop[];
};

export type AttackEvidenceRef = {
  kind: string;
  value: string;
};

export type AttackTechniqueMapping = {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  reference_url: string;
  confidence: string;
  rationales: string[];
  evidence: AttackEvidenceRef[];
};

export type AttackMapping = {
  matrix: string;
  techniques: AttackTechniqueMapping[];
  tactics: string[];
  context_codes: string[];
  notes: string[];
};

export type LookalikeField = "from_addr" | "reply_to" | "return_path";
export type LookalikeMatchType = "brand_affix" | "deceptive_subdomain" | "edit_distance" | "homoglyph";
export type LookalikeConfidence = "high" | "medium" | "low";

export type LookalikeMatch = {
  field: LookalikeField;
  address: string;
  observed_domain: string;
  observed_registrable_domain?: string | null;
  target_domain: string;
  target_registrable_domain: string;
  match_type: LookalikeMatchType;
  confidence: LookalikeConfidence;
  distance?: number | null;
  reasons: string[];
};

export type LookalikeAnalysis = {
  target_domain: string;
  target_registrable_domain: string;
  has_suspected_lookalikes: boolean;
  matches: LookalikeMatch[];
  summary: string;
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
  url_analysis_json?: UrlAnalysis[] | null;
  reporter_hash?: string | null;
  mailbox_domain?: string | null;
  raw_source?: string | null;
  original_filename?: string | null;
  original_content_type?: string | null;
  original_size_bytes?: number | null;
  original_sha256?: string | null;
  has_original_message: boolean;
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
  campaign_id?: number | null;
  campaign_assignment_method?: CampaignAssignmentMethod | null;
  campaign_assignment_score?: number | null;
  campaign_assignment_explanation_json?: Record<string, unknown> | null;
  auth_summary?: ReportAuthSummary | null;
  attack_mapping?: AttackMapping | null;
  lookalike_analysis?: LookalikeAnalysis | null;
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

export type FileIngestItem = {
  filename: string;
  status: "INGESTED" | "FAILED";
  report_id?: number | null;
  campaign_id?: number | null;
  risk_score?: number | null;
  error_code?: string | null;
  error_message?: string | null;
};

export type FileIngestBatchResult = {
  items: FileIngestItem[];
  ingested_count: number;
  failed_count: number;
};

export type Campaign = {
  id: number;
  campaign_key: string;
  name?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  report_count: number;
  confidence_score?: number | null;
  is_locked: boolean;
  lock_reason?: string | null;
  algorithm_version: string;
  created_at: string;
  updated_at: string;
};

export type CampaignEventAction =
  | "AUTO_ASSIGN"
  | "MANUAL_REASSIGN"
  | "MERGE"
  | "SPLIT"
  | "LOCK"
  | "UNLOCK"
  | "RECLUSTER";

export type CampaignEvent = {
  id: number;
  campaign_id: number;
  action: CampaignEventAction;
  report_id?: number | null;
  from_campaign_id?: number | null;
  to_campaign_id?: number | null;
  score?: number | null;
  features_json?: Record<string, unknown> | null;
  actor_user_id?: number | null;
  actor_api_key_id?: number | null;
  actor_snapshot: string;
  created_at: string;
};

export type CampaignReclusterResult = {
  processed_reports: number;
  reassigned_reports: number;
  created_campaigns: number;
  skipped_manual_reports: number;
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

export async function deleteReport(id: number): Promise<void> {
  return request<void>(`/api/reports/${id}`, {
    method: "DELETE",
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

export async function uploadReportFiles(files: File[]): Promise<FileIngestBatchResult> {
  const token = getAccessToken();
  const form = new FormData();
  for (const file of files) {
    form.append("files", file);
  }

  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}/api/report-files`, {
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

export async function downloadReportAttachment(
  reportId: number,
  attachmentId: number,
  filename?: string | null
): Promise<EvidenceDownload> {
  const token = getAccessToken();
  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}/api/reports/${reportId}/attachments/${attachmentId}/download`, {
    method: "GET",
    headers,
  });

  if (res.status === 401 && unauthorizedHandler) {
    unauthorizedHandler();
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Attachment download failed: ${res.status}`);
  }

  return {
    blob: await res.blob(),
    filename: parseDownloadFilename(res) || filename || "attachment.bin",
  };
}

export async function downloadReportOriginalMessage(
  reportId: number,
  filename?: string | null
): Promise<EvidenceDownload> {
  const token = getAccessToken();
  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}/api/reports/${reportId}/original-message/download`, {
    method: "GET",
    headers,
  });

  if (res.status === 401 && unauthorizedHandler) {
    unauthorizedHandler();
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Original message download failed: ${res.status}`);
  }

  return {
    blob: await res.blob(),
    filename: parseDownloadFilename(res) || filename || "original-message.bin",
  };
}

export async function fetchCampaigns(params?: {
  q?: string;
  source?: "UPLOAD" | "AUTO";
  status?: "OPEN" | "BENIGN" | "PHISHING";
  locked?: boolean;
  min_confidence?: number;
  limit?: number;
  cursor?: number;
}): Promise<Campaign[]> {
  const search = new URLSearchParams();
  if (params?.q) search.set("q", params.q);
  if (params?.source) search.set("source", params.source);
  if (params?.status) search.set("status", params.status);
  if (typeof params?.locked === "boolean") search.set("locked", String(params.locked));
  if (typeof params?.min_confidence === "number") search.set("min_confidence", String(params.min_confidence));
  if (typeof params?.limit === "number") search.set("limit", String(params.limit));
  if (typeof params?.cursor === "number") search.set("cursor", String(params.cursor));
  const suffix = search.toString();
  return request<Campaign[]>(suffix ? `/api/campaigns?${suffix}` : "/api/campaigns");
}

export async function fetchCampaign(campaignId: number): Promise<Campaign> {
  return request<Campaign>(`/api/campaigns/${campaignId}`);
}

export async function fetchCampaignReports(
  campaignId: number,
  params?: { limit?: number; offset?: number }
): Promise<Report[]> {
  const search = new URLSearchParams();
  if (params?.limit) search.set("limit", String(params.limit));
  if (params?.offset) search.set("offset", String(params.offset));
  const suffix = search.toString();
  return request<Report[]>(suffix ? `/api/campaigns/${campaignId}/reports?${suffix}` : `/api/campaigns/${campaignId}/reports`);
}

export async function fetchCampaignEvents(campaignId: number, limit = 200): Promise<CampaignEvent[]> {
  return request<CampaignEvent[]>(`/api/campaigns/${campaignId}/events?limit=${limit}`);
}

export async function reclusterCampaigns(payload: {
  start?: string | null;
  end?: string | null;
}): Promise<CampaignReclusterResult> {
  return request<CampaignReclusterResult>("/api/campaigns/recluster", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function mergeCampaigns(payload: {
  source_campaign_ids: number[];
  target_campaign_id: number;
}): Promise<Campaign> {
  return request<Campaign>("/api/campaigns/merge", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function splitCampaign(payload: {
  source_campaign_id: number;
  report_ids: number[];
  new_campaign_name?: string | null;
}): Promise<Campaign> {
  return request<Campaign>("/api/campaigns/split", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function reassignReportCampaign(
  reportId: number,
  payload: { target_campaign_id?: number | null; create_new: boolean; new_campaign_name?: string | null }
): Promise<Report> {
  return request<Report>(`/api/reports/${reportId}/campaign/reassign`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function lockCampaign(campaignId: number, reason?: string | null): Promise<Campaign> {
  return request<Campaign>(`/api/campaigns/${campaignId}/lock`, {
    method: "POST",
    body: JSON.stringify({ reason: reason || null }),
  });
}

export async function unlockCampaign(campaignId: number): Promise<Campaign> {
  return request<Campaign>(`/api/campaigns/${campaignId}/unlock`, {
    method: "POST",
  });
}

type EvidenceDownload = {
  blob: Blob;
  filename: string | null;
};

function parseDownloadFilename(res: Response): string | null {
  const disposition = res.headers.get("content-disposition") || "";
  const encodedMatch = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (encodedMatch?.[1]) {
    try {
      return decodeURIComponent(encodedMatch[1]);
    } catch {
      return encodedMatch[1];
    }
  }
  const quotedMatch = disposition.match(/filename=\"([^\"]+)\"/i);
  if (quotedMatch?.[1]) {
    return quotedMatch[1];
  }
  return null;
}

async function downloadEvidence(path: string): Promise<EvidenceDownload> {
  const token = getAccessToken();
  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}${path}`, {
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
  return {
    blob: await res.blob(),
    filename: parseDownloadFilename(res),
  };
}

async function downloadReportEvidence(reportId: number, extension: "md" | "pdf" | "json"): Promise<EvidenceDownload> {
  return downloadEvidence(`/api/reports/${reportId}/evidence.${extension}`);
}

export async function downloadReportEvidenceMarkdown(reportId: number): Promise<EvidenceDownload> {
  return downloadReportEvidence(reportId, "md");
}

export async function downloadReportEvidencePdf(reportId: number): Promise<EvidenceDownload> {
  return downloadReportEvidence(reportId, "pdf");
}

export async function downloadReportEvidenceJson(reportId: number): Promise<EvidenceDownload> {
  return downloadReportEvidence(reportId, "json");
}

export async function downloadReportIocsJson(reportId: number): Promise<EvidenceDownload> {
  return downloadEvidence(`/api/reports/${reportId}/iocs.json`);
}

export async function downloadReportIocsCsv(reportId: number): Promise<EvidenceDownload> {
  return downloadEvidence(`/api/reports/${reportId}/iocs.csv`);
}

export async function downloadCampaignEvidenceMarkdown(campaignId: number): Promise<EvidenceDownload> {
  return downloadEvidence(`/api/campaigns/${campaignId}/evidence.md`);
}

export async function downloadCampaignEvidencePdf(campaignId: number): Promise<EvidenceDownload> {
  return downloadEvidence(`/api/campaigns/${campaignId}/evidence.pdf`);
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

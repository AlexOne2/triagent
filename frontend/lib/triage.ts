import { TriageBucket } from "./api";

export type VisibleTriageBucket = Extract<TriageBucket, "NEEDS_INVESTIGATION" | "LIKELY_BENIGN" | "UNCERTAIN">;

export const ALL_TRIAGE_BUCKET_ORDER: TriageBucket[] = [
  "NEEDS_INVESTIGATION",
  "AUTOMATION_READY",
  "BULK_SPAM",
  "LIKELY_BENIGN",
  "UNCERTAIN",
];

export const TRIAGE_BUCKET_ORDER: VisibleTriageBucket[] = [
  "NEEDS_INVESTIGATION",
  "LIKELY_BENIGN",
  "UNCERTAIN",
];

type TriageBucketMeta = {
  label: string;
  shortLabel: string;
  description: string;
  emptyState: string;
  tone: "focus" | "benign" | "uncertain";
};

const TRIAGE_BUCKET_META: Record<VisibleTriageBucket, TriageBucketMeta> = {
  NEEDS_INVESTIGATION: {
    label: "Needs investigation",
    shortLabel: "Needs review",
    description: "Messages that deserve analyst attention.",
    emptyState: "No analyst-worthy reports match the current search.",
    tone: "focus",
  },
  LIKELY_BENIGN: {
    label: "Likely benign",
    shortLabel: "Benign",
    description: "Likely safe or low-value mail that should not consume analyst time.",
    emptyState: "No likely benign reports match the current search.",
    tone: "benign",
  },
  UNCERTAIN: {
    label: "Uncertain",
    shortLabel: "Uncertain",
    description: "Mixed or incomplete signals that still need lightweight review.",
    emptyState: "No uncertain reports match the current search.",
    tone: "uncertain",
  },
};

const DISPLAY_BUCKET_MAP: Record<TriageBucket, VisibleTriageBucket> = {
  NEEDS_INVESTIGATION: "NEEDS_INVESTIGATION",
  AUTOMATION_READY: "NEEDS_INVESTIGATION",
  BULK_SPAM: "LIKELY_BENIGN",
  LIKELY_BENIGN: "LIKELY_BENIGN",
  UNCERTAIN: "UNCERTAIN",
};

const TRIAGE_REASON_LABELS: Record<string, string> = {
  SUSPICIOUS_ATTACHMENT: "Attachment",
  CREDENTIAL_LINK: "Credential lure",
  SUSPICIOUS_REDIRECT: "Redirect chain",
  RISKY_LINK: "Risky link",
  BEC_IMPERSONATION: "BEC",
  FINANCE_LANGUAGE: "Finance language",
  THREAD_HIJACK_SIGNAL: "Thread hijack",
  LOOKALIKE_DOMAIN: "Lookalike",
  AUTH_FAILURES: "Auth failure",
  AUTH_ROUTING_MISMATCH: "Routing mismatch",
  LIST_HEADERS: "List headers",
  LIST_UNSUBSCRIBE: "Unsubscribe",
  ONE_CLICK_UNSUBSCRIBE: "One-click",
  BULK_PRECEDENCE: "Bulk precedence",
  AUTO_SUBMITTED: "Auto-submitted",
  MARKETING_CONTENT: "Marketing",
  BENIGN_TRANSACTIONAL: "Transactional",
  CONFLICTING_SIGNALS: "Mixed signals",
};

export function getTriageBucketMeta(bucket: TriageBucket | VisibleTriageBucket): TriageBucketMeta {
  return TRIAGE_BUCKET_META[toVisibleTriageBucket(bucket)];
}

export function isVisibleTriageBucket(value: unknown): value is VisibleTriageBucket {
  return typeof value === "string" && TRIAGE_BUCKET_ORDER.includes(value as VisibleTriageBucket);
}

export function toVisibleTriageBucket(bucket: TriageBucket | VisibleTriageBucket): VisibleTriageBucket {
  return DISPLAY_BUCKET_MAP[bucket as TriageBucket] || (bucket as VisibleTriageBucket);
}

export function expandVisibleTriageBuckets(buckets: VisibleTriageBucket[]): TriageBucket[] {
  const expanded = new Set<TriageBucket>();
  for (const bucket of buckets) {
    if (bucket === "NEEDS_INVESTIGATION") {
      expanded.add("NEEDS_INVESTIGATION");
      expanded.add("AUTOMATION_READY");
      continue;
    }
    if (bucket === "LIKELY_BENIGN") {
      expanded.add("BULK_SPAM");
      expanded.add("LIKELY_BENIGN");
      continue;
    }
    expanded.add("UNCERTAIN");
  }
  return Array.from(expanded);
}

export function formatTriageReasonCode(code: string): string {
  return TRIAGE_REASON_LABELS[code] || code.replace(/_/g, " ").toLowerCase();
}

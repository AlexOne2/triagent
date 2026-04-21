import { TriageBucket } from "./api";

export const TRIAGE_BUCKET_ORDER: TriageBucket[] = [
  "NEEDS_INVESTIGATION",
  "AUTOMATION_READY",
  "BULK_SPAM",
  "LIKELY_BENIGN",
  "UNCERTAIN",
];

type TriageBucketMeta = {
  label: string;
  shortLabel: string;
  description: string;
  emptyState: string;
  tone: "focus" | "automation" | "spam" | "benign" | "uncertain";
};

export const TRIAGE_BUCKET_META: Record<TriageBucket, TriageBucketMeta> = {
  NEEDS_INVESTIGATION: {
    label: "Needs investigation",
    shortLabel: "Needs review",
    description: "High-value cases that warrant analyst attention.",
    emptyState: "No analyst-worthy reports match the current search.",
    tone: "focus",
  },
  AUTOMATION_READY: {
    label: "Automation-ready",
    shortLabel: "Automation",
    description: "Likely malicious, but commodity enough for automation-first handling.",
    emptyState: "No automation-ready reports match the current search.",
    tone: "automation",
  },
  BULK_SPAM: {
    label: "Spam / graymail",
    shortLabel: "Spam",
    description: "Bulk or nuisance mail that does not justify human investigation.",
    emptyState: "No spam or graymail reports match the current search.",
    tone: "spam",
  },
  LIKELY_BENIGN: {
    label: "Likely benign",
    shortLabel: "Benign",
    description: "Routine operational mail that currently looks low risk.",
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

export function getTriageBucketMeta(bucket: TriageBucket): TriageBucketMeta {
  return TRIAGE_BUCKET_META[bucket];
}

export function isTriageBucket(value: unknown): value is TriageBucket {
  return typeof value === "string" && TRIAGE_BUCKET_ORDER.includes(value as TriageBucket);
}

export function formatTriageReasonCode(code: string): string {
  return TRIAGE_REASON_LABELS[code] || code.replace(/_/g, " ").toLowerCase();
}

import { useEffect, useState } from "react";
import { CLASSIFICATION_CODES, ClassificationCode, Report } from "./api";
import { VisibleTriageBucket, isVisibleTriageBucket } from "./triage";

const STORAGE_KEY_PREFIX = "triagent.queueFilters.v2";
const STATUS_VALUES: Report["status"][] = ["OPEN", "PHISHING", "BENIGN"];

type StoredQueueFilters = {
  query?: string;
  statuses?: Report["status"][];
  triageBuckets?: VisibleTriageBucket[];
  classifications?: ClassificationCode[];
};

function isStatus(value: unknown): value is Report["status"] {
  return typeof value === "string" && STATUS_VALUES.includes(value as Report["status"]);
}

function isClassification(value: unknown): value is ClassificationCode {
  return typeof value === "string" && CLASSIFICATION_CODES.includes(value as ClassificationCode);
}

function normalizeStoredFilters(value: unknown): Required<StoredQueueFilters> {
  const parsed = typeof value === "object" && value !== null ? (value as StoredQueueFilters) : {};
  return {
    query: typeof parsed.query === "string" ? parsed.query : "",
    statuses: Array.isArray(parsed.statuses) ? parsed.statuses.filter(isStatus) : [],
    triageBuckets: Array.isArray(parsed.triageBuckets) ? parsed.triageBuckets.filter(isVisibleTriageBucket) : [],
    classifications: Array.isArray(parsed.classifications)
      ? parsed.classifications.filter(isClassification)
      : [],
  };
}

export function usePersistedQueueFilters(scope: string) {
  const storageKey = `${STORAGE_KEY_PREFIX}.${scope}`;
  const [ready, setReady] = useState(false);
  const [draftQuery, setDraftQuery] = useState("");
  const [query, setQuery] = useState("");
  const [triageFilters, setTriageFilters] = useState<VisibleTriageBucket[]>([]);
  const [statusFilters, setStatusFilters] = useState<Report["status"][]>([]);
  const [classificationFilters, setClassificationFilters] = useState<ClassificationCode[]>([]);

  useEffect(() => {
    if (typeof window === "undefined") {
      setReady(true);
      return;
    }
    try {
      const raw = window.localStorage.getItem(storageKey);
      if (!raw) {
        setReady(true);
        return;
      }
      const stored = normalizeStoredFilters(JSON.parse(raw));
      setDraftQuery(stored.query);
      setQuery(stored.query);
      setStatusFilters(stored.statuses);
      setTriageFilters(stored.triageBuckets);
      setClassificationFilters(stored.classifications);
    } catch {
      window.localStorage.removeItem(storageKey);
    } finally {
      setReady(true);
    }
  }, [storageKey]);

  useEffect(() => {
    if (!ready || typeof window === "undefined") {
      return;
    }
    const payload: Required<StoredQueueFilters> = {
      query,
      statuses: statusFilters,
      triageBuckets: triageFilters,
      classifications: classificationFilters,
    };
    window.localStorage.setItem(storageKey, JSON.stringify(payload));
  }, [ready, query, statusFilters, triageFilters, classificationFilters, storageKey]);

  const applyDraftQuery = () => {
    const normalized = draftQuery.trim();
    setDraftQuery(normalized);
    setQuery(normalized);
  };

  const clearFilters = () => {
    setDraftQuery("");
    setQuery("");
    setTriageFilters([]);
    setStatusFilters([]);
    setClassificationFilters([]);
  };

  return {
    ready,
    draftQuery,
    setDraftQuery,
    query,
    applyDraftQuery,
    clearFilters,
    triageFilters,
    setTriageFilters,
    statusFilters,
    setStatusFilters,
    classificationFilters,
    setClassificationFilters,
  };
}

import { useRouter } from "next/router";
import { useEffect } from "react";

import { useAuth } from "../lib/auth-context";
import { VisibleTriageBucket, isVisibleTriageBucket } from "../lib/triage";

const FILTER_STORAGE_KEY = "triagent.queueFilters.v2.uploads";

function resolveBucket(value: string | string[] | undefined): VisibleTriageBucket {
  if (typeof value === "string" && isVisibleTriageBucket(value)) {
    return value;
  }
  return "NEEDS_INVESTIGATION";
}

export default function DemoCapturePage() {
  const router = useRouter();
  const { loading, isAuthenticated, loginDemo } = useAuth();

  useEffect(() => {
    if (loading || !router.isReady) {
      return;
    }

    const bucket = resolveBucket(router.query.bucket);

    if (!isAuthenticated) {
      void loginDemo();
      return;
    }

    window.localStorage.setItem(
      FILTER_STORAGE_KEY,
      JSON.stringify({
        query: "",
        statuses: [],
        triageBuckets: [bucket],
        classifications: [],
      })
    );
    window.location.replace("/reports");
  }, [isAuthenticated, loading, loginDemo, router.isReady, router.query.bucket]);

  return (
    <main className="full">
      <p>Preparing demo capture...</p>
    </main>
  );
}

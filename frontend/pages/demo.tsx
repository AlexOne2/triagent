import { useRouter } from "next/router";
import { useEffect, useMemo, useState } from "react";

import { useAuth } from "../lib/auth-context";

const DEMO_STEP_TIMELINE = [
  {
    title: "Sign in to the shared demo",
    copy: "The public demo opens without credentials and uses a read-only seeded workspace.",
  },
  {
    title: "Load the seeded reports",
    copy: "Queue, evidence, assist draft, audit history, and exports are already prepared.",
  },
  {
    title: "Open the analyst workspace",
    copy: "Redirecting as soon as the demo dataset is ready.",
  },
] as const;

export default function DemoPage() {
  const router = useRouter();
  const { loading, isAuthenticated, roles, loginDemo } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [started, setStarted] = useState(false);
  const [elapsedMs, setElapsedMs] = useState(0);

  useEffect(() => {
    void router.prefetch("/reports");
  }, [router]);

  useEffect(() => {
    if (!started || error) {
      return;
    }
    const interval = window.setInterval(() => {
      setElapsedMs((current) => current + 350);
    }, 350);
    return () => window.clearInterval(interval);
  }, [error, started]);

  const stepIndex = useMemo(() => {
    if (elapsedMs > 7000) return 2;
    if (elapsedMs > 2500) return 1;
    return 0;
  }, [elapsedMs]);

  const slowLoad = elapsedMs > 9000;

  useEffect(() => {
    if (loading || started) {
      return;
    }
    if (isAuthenticated) {
      window.location.replace("/reports");
      return;
    }

    setStarted(true);
    setElapsedMs(0);
    let cancelled = false;
    void (async () => {
      try {
        await loginDemo();
        if (!cancelled) {
          window.location.replace("/reports");
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Demo login failed");
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, loading, loginDemo, roles, router, started]);

  function retry() {
    setError(null);
    setElapsedMs(0);
    setStarted(false);
  }

  return (
    <main className="demo-entry">
      <section className="demo-entry-content">
        <p className="demo-entry-kicker">Opening demo workspace</p>
        <h1 className="demo-entry-title">Preparing the read-only demo.</h1>
        <p className="demo-entry-copy">
          This signs you into a shared seeded workspace, so the public demo opens quickly and does not create a fresh
          private dataset on every visit.
        </p>

        <div className="demo-entry-progress" aria-hidden="true">
          <div className="demo-entry-progress-fill" style={{ width: `${Math.min(90, 24 + stepIndex * 26)}%` }} />
        </div>

        <div className="demo-entry-steps">
          {DEMO_STEP_TIMELINE.map((step, index) => (
            <div
              key={step.title}
              className={`demo-entry-step ${index === stepIndex ? "active" : ""} ${index < stepIndex ? "done" : ""}`.trim()}
            >
              <h2>{step.title}</h2>
              <p>{step.copy}</p>
            </div>
          ))}
        </div>

        {error ? (
          <div className="demo-entry-feedback">
            <p className="auth-error">{error}</p>
            <button type="button" className="resolve-button landing-primary-cta demo-entry-button" onClick={retry}>
              Retry demo
            </button>
          </div>
        ) : slowLoad ? (
          <div className="demo-entry-feedback">
            <p className="demo-entry-slow-note">
              Still working. The very first demo load can take a few extra seconds while the shared demo workspace is
              prepared on the server.
            </p>
            <button type="button" className="resolve-button secondary demo-entry-button" onClick={retry}>
              Restart demo setup
            </button>
          </div>
        ) : null}
      </section>
    </main>
  );
}

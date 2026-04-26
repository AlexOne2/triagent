import Image from "next/image";
import Link from "next/link";
import { FormEvent, useState } from "react";

import { createWaitlistLead } from "../lib/api";
import { useAuth } from "../lib/auth-context";

const WORKFLOW_STEPS = [
  {
    title: "Email ingestion",
    copy: "Start from the original reported message, preserve the source, and normalize the evidence immediately.",
  },
  {
    title: "Analyst-first prioritization",
    copy: "Separate routine benign noise from the cases that deserve real analyst time and deeper review.",
  },
  {
    title: "Evidence-first console",
    copy: "Authentication, URLs, attachments, raw source, and notes stay together in the same investigation surface.",
  },
  {
    title: "Resolution and export",
    copy: "Close the case with a classification, audit history, and exportable evidence package instead of rebuilding the story by hand.",
  },
];

const WHY_TRIAGENT = [
  {
    title: "Auto-categorize low-value reports",
    copy: "Most user-reported email does not deserve a full investigation. Triagent helps separate likely benign noise before analysts spend time on it.",
  },
  {
    title: "Escalate only analyst-worthy cases",
    copy: "The cases with stronger evidence are routed into analyst review with an assist draft and supporting signals already packaged.",
  },
  {
    title: "Keep the evidence and exports together",
    copy: "When a case does need review, the original message, supporting artifacts, and exportable case record stay in the same workflow.",
  },
];

const FAQS = [
  {
    question: "What does Triagent actually do today?",
    answer:
      "The current product demonstrates reported-email triage, evidence review, analyst resolution, audit history, and PDF / IOC export on a curated demo dataset.",
  },
  {
    question: "How is this different from a spam filter or SEG?",
    answer:
      "Triagent is not a secure email gateway replacement. It is an analyst workflow for handling user-reported suspicious emails after they reach the mailbox.",
  },
  {
    question: "Who is this for right now?",
    answer:
      "The current wedge is internal SOC / SecOps teams and MSSPs that repeatedly handle phishing reports and need a tighter investigation and case-close workflow.",
  },
  {
    question: "Is it suitable for MSSPs?",
    answer:
      "Yes. MSSP handling is part of the target wedge because the same repetitive review and evidence-packaging burden shows up even more strongly in service environments.",
  },
  {
    question: "What is automated versus analyst-reviewed?",
    answer:
      "Prioritization, evidence gathering, and packaging are assisted. The final disposition and classification remain analyst-controlled in the current product story.",
  },
  {
    question: "What does the demo login lead to?",
    answer:
      "It signs you into a shared read-only demo workspace with a seeded dataset, so you can explore the product without credentials or per-visitor provisioning delays.",
  },
];

export default function Home() {
  const { isAuthenticated, roles } = useAuth();
  const [name, setName] = useState("");
  const [workEmail, setWorkEmail] = useState("");
  const [company, setCompany] = useState("");
  const [role, setRole] = useState("");
  const [notes, setNotes] = useState("");
  const [showDetails, setShowDetails] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const isDemoUser = roles.includes("DEMO");
  const demoHref = !isAuthenticated ? "/demo" : "/reports";
  const demoLabel = !isAuthenticated ? "Try it here" : isDemoUser ? "Open demo" : "Open workspace";

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setSuccess(null);

    try {
      const result = await createWaitlistLead({
        name,
        work_email: workEmail,
        company,
        role,
        notes,
        source: "landing_page",
      });
      setSuccess(
        result.already_exists
          ? "You're already on the waitlist. We updated your latest details."
          : "You're on the waitlist. We'll reach out when we open more hands-on demo slots."
      );
      setName("");
      setWorkEmail("");
      setCompany("");
      setRole("");
      setNotes("");
      setShowDetails(false);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Waitlist signup failed";
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="landing-page">
      <section className="landing-hero-shell">
        <header className="landing-topbar">
          <div className="landing-brand">Triagent</div>
          <nav className="landing-nav" aria-label="Landing">
            <a href="#why-triagent" className="landing-nav-link">
              Why Triagent
            </a>
            <a href="#how-it-works" className="landing-nav-link">
              How it works
            </a>
            <a href="#mssps" className="landing-nav-link">
              MSSPs
            </a>
            <a href="#faq" className="landing-nav-link">
              FAQ
            </a>
            <Link href="/login" className="landing-nav-button">
              Sign in
            </Link>
          </nav>
        </header>

        <div className="landing-hero">
          <div className="landing-hero-copy">
            <span className="landing-kicker">Evidence-first phishing triage</span>
            <h1 className="landing-title">Triage reported phishing faster.</h1>
            <p className="landing-subtitle">
              Triagent helps SOC teams and MSSPs automatically separate analyst-worthy cases from low-value reported
              email, then review the evidence, resolve the case, and export a defensible record.
            </p>
            <div className="landing-actions">
              <Link href={demoHref} className="resolve-button landing-primary-cta">
                {demoLabel}
              </Link>
              <a href="#waitlist" className="resolve-button secondary landing-secondary-button">
                Join waitlist
              </a>
            </div>
            <p className="landing-cta-note">
              The public demo opens a shared read-only workspace and shows queueing, evidence review, assist draft,
              audit history, and PDF / IOC export.
            </p>
          </div>
        </div>

        <div className="landing-screenshot-frame">
          <Image
            className="landing-screenshot-image"
            src="/ResolutionFlow.png"
            alt="Actual Triagent prototype screenshot showing reported-email triage and the assist draft resolution flow."
            priority
            width={2048}
            height={1200}
          />
          <p className="landing-screenshot-note">
            Actual screenshot from the current prototype. The public demo uses this same read-only workflow surface.
          </p>
        </div>
      </section>

      <section id="why-triagent" className="landing-section landing-story-section">
        <div className="landing-section-copy">
          <span className="landing-kicker">Why Triagent</span>
          <h2 className="landing-section-title landing-section-title-compact">Auto-categorize reported email before analysts dig in.</h2>
          <p>
            The wedge is not just less tool-hopping. It is automatic separation between low-value reported mail and the
            cases that deserve analyst attention, with the evidence and draft resolution already attached when a human
            does need to step in.
          </p>
        </div>
        <div className="landing-story-grid">
          <div className="landing-story-visual">
            <article className="landing-story-shot">
              <div className="landing-story-shot-header">
                <span className="landing-story-chip landing-story-chip-alert">Needs investigation</span>
                <p>This real queue view shows only the reports Triagent routes into analyst review.</p>
              </div>
              <Image
                className="landing-story-shot-image"
                src="/QueueNeedsInvestigation.png"
                alt="Actual Triagent screenshot showing the filtered needs investigation queue with analyst-worthy reported emails."
                width={1540}
                height={620}
              />
            </article>

            <p className="landing-story-note">
              Low-value reported mail stays out of this queue and can be handled in a separate likely benign path
              before an analyst opens the case.
            </p>
          </div>
          <div className="landing-story-copy">
            {WHY_TRIAGENT.map((item) => (
              <article key={item.title} className="landing-story-point">
                <h3>{item.title}</h3>
                <p>{item.copy}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section id="how-it-works" className="landing-section">
        <div className="landing-section-copy landing-section-copy-wide">
          <span className="landing-kicker">How it works</span>
          <h2 className="landing-section-title">Triagent fits the existing reported-email workflow instead of forcing a new one.</h2>
          <p>
            The current product story is intentionally narrow: start from reported mail, package the evidence, help the
            analyst decide faster, and close the case cleanly.
          </p>
        </div>
        <div className="landing-workflow-grid">
          {WORKFLOW_STEPS.map((item, index) => (
            <article key={item.title} className="landing-workflow-card">
              <span className="landing-workflow-step">{String(index + 1).padStart(2, "0")}</span>
              <h3>{item.title}</h3>
              <p>{item.copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="mssps" className="landing-section">
        <div className="landing-section-copy landing-section-copy-wide">
          <span className="landing-kicker">Internal teams and MSSPs</span>
          <h2 className="landing-section-title">The wedge works for internal SOCs and service teams, but the buying language is slightly different.</h2>
        </div>
        <div className="landing-fit-grid">
          <article className="landing-fit-card">
            <h3>Internal SOC / SecOps</h3>
            <ul className="landing-list">
              <li>Reduce repeated analyst work on user-reported suspicious email.</li>
              <li>Keep the evidence record and analyst decision in one place.</li>
              <li>Produce cleaner outputs for auditability, incident review, and handoff.</li>
            </ul>
          </article>
          <article className="landing-fit-card">
            <h3>MSSP workflows</h3>
            <ul className="landing-list">
              <li>Handle recurring phishing reports across customers with a more repeatable process.</li>
              <li>Preserve case quality and evidence packaging without rebuilding every report manually.</li>
              <li>Give service leads a clearer story around triage throughput and case-close consistency.</li>
            </ul>
          </article>
        </div>
      </section>

      <section className="landing-proof-grid">
        <article className="landing-proof-card">
          <span className="landing-kicker">What the demo proves</span>
          <h2 className="landing-proof-title">Show the workflow, not just the verdict.</h2>
          <ul className="landing-list">
            <li>Queue reported emails by analyst priority instead of treating every report as equal.</li>
            <li>Review auth, URLs, attachments, raw source, and analyst notes in the same case workspace.</li>
            <li>Resolve, classify, and export evidence from the same report without switching tools.</li>
          </ul>
        </article>
        <article className="landing-proof-card">
          <span className="landing-kicker">Current product line</span>
          <h2 className="landing-proof-title">Narrow wedge first, broader workflow later.</h2>
          <ul className="landing-list">
            <li>Current story: evidence-first phishing triage for analyst teams.</li>
            <li>Current proof: validation-grade analyst workflow, not a production-wide platform claim.</li>
            <li>Current CTA: demo login and waitlist, not a broad self-serve pricing motion.</li>
          </ul>
        </article>
      </section>

      <section id="faq" className="landing-section">
        <div className="landing-section-copy landing-section-copy-wide">
          <span className="landing-kicker">Frequently asked questions</span>
          <h2 className="landing-section-title">Handle the buyer objections on the page instead of leaving them for the call.</h2>
        </div>
        <div className="landing-faq-list">
          {FAQS.map((item) => (
            <details key={item.question} className="landing-faq-item">
              <summary>{item.question}</summary>
              <p>{item.answer}</p>
            </details>
          ))}
        </div>
      </section>

      <section id="waitlist" className="landing-waitlist-section">
        <div className="landing-waitlist-copy">
          <span className="landing-kicker">Request early access</span>
          <h2 className="landing-section-title">Start with your work email. Add more context only if you want a more tailored follow-up.</h2>
          <p>We’ll use this for early demos, design-partner discussions, and product validation follow-up.</p>
        </div>
        <form className="landing-form" onSubmit={onSubmit}>
          <div className="landing-form-primary">
            <input
              id="waitlist-email"
              className="input"
              type="email"
              value={workEmail}
              onChange={(event) => setWorkEmail(event.target.value)}
              autoComplete="email"
              placeholder="Work email"
              required
            />
            <button className="resolve-button landing-form-submit" type="submit" disabled={submitting}>
              {submitting ? "Joining..." : "Join waitlist"}
            </button>
          </div>

          <button
            className="landing-details-toggle"
            type="button"
            onClick={() => setShowDetails((value) => !value)}
            aria-expanded={showDetails}
          >
            {showDetails ? "Hide extra context" : "Add name, company, role, and notes"}
          </button>

          {showDetails ? (
            <>
              <div className="landing-form-grid">
                <div className="landing-form-field">
                  <label htmlFor="waitlist-name">Name</label>
                  <input
                    id="waitlist-name"
                    className="input"
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    autoComplete="name"
                  />
                </div>
                <div className="landing-form-field">
                  <label htmlFor="waitlist-company">Company</label>
                  <input
                    id="waitlist-company"
                    className="input"
                    value={company}
                    onChange={(event) => setCompany(event.target.value)}
                    autoComplete="organization"
                  />
                </div>
                <div className="landing-form-field">
                  <label htmlFor="waitlist-role">Role</label>
                  <input
                    id="waitlist-role"
                    className="input"
                    value={role}
                    onChange={(event) => setRole(event.target.value)}
                    autoComplete="organization-title"
                  />
                </div>
              </div>
              <div className="landing-form-field">
                <label htmlFor="waitlist-notes">What are you trying to improve?</label>
                <textarea
                  id="waitlist-notes"
                  className="landing-textarea"
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                  placeholder="Examples: phishing mailbox backlog, MSSP customer handling, evidence export, or auditability."
                />
              </div>
            </>
          ) : null}

          {error ? <p className="auth-error">{error}</p> : null}
          {success ? <p className="landing-success">{success}</p> : null}

          <div className="landing-form-actions">
            <span className="landing-form-note">No spam. We’ll only use this to coordinate access and follow-up.</span>
          </div>
        </form>
      </section>
    </main>
  );
}

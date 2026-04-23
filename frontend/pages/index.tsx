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
    title: "Built for reported-email triage",
    copy: "Triagent starts where the secure email gateway stops: after a user reports something suspicious.",
  },
  {
    title: "Analyst in the loop",
    copy: "The product helps prioritize and package evidence, but the analyst still owns the decision.",
  },
  {
    title: "Evidence packaged for action",
    copy: "Preserve the original message, collect the supporting signals, and export the case without tool-hopping.",
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
      "It leads into the current analyst workspace so prospects can see the queue, evidence review, analyst resolution flow, and exports directly.",
  },
];

export default function Home() {
  const { isAuthenticated } = useAuth();
  const [name, setName] = useState("");
  const [workEmail, setWorkEmail] = useState("");
  const [company, setCompany] = useState("");
  const [role, setRole] = useState("");
  const [notes, setNotes] = useState("");
  const [showDetails, setShowDetails] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const demoHref = isAuthenticated ? "/reports" : "/login";
  const demoLabel = isAuthenticated ? "Open analyst workspace" : "Open demo login";

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
              Current demo shows queueing, evidence review, analyst resolution, audit history, and PDF / IOC export.
            </p>
          </div>
        </div>

        <div className="landing-screenshot-frame" aria-hidden="true">
          <div className="landing-screenshot-bar">
            <div className="landing-screenshot-brand">Triagent</div>
            <div className="landing-screenshot-nav">
              <span>Dashboard</span>
              <span>Uploads</span>
              <span>In-tray</span>
              <span>Audit</span>
            </div>
          </div>
          <div className="landing-screenshot-body">
            <div className="landing-screenshot-breadcrumb">Uploads &gt; Urgent: Your Microsoft 365 password expires today</div>
            <div className="landing-screenshot-title-row">
              <div>
                <h2 className="landing-screenshot-title">Urgent: Your Microsoft 365 password expires today</h2>
                <div className="landing-screenshot-badges">
                  <span className="landing-screenshot-badge landing-screenshot-badge-danger">Needs investigation</span>
                  <span className="landing-screenshot-badge">Credential lure</span>
                  <span className="landing-screenshot-badge">Redirect chain</span>
                </div>
              </div>
              <button className="landing-screenshot-resolve">Resolve</button>
            </div>
            <div className="landing-screenshot-tabs">
              <span className="active">Details</span>
              <span>Authentication</span>
              <span>URLs</span>
              <span>Attachments</span>
              <span>Source</span>
            </div>
            <div className="landing-screenshot-split">
              <div className="landing-screenshot-panel">
                <div className="landing-screenshot-field">
                  <label>From</label>
                  <span>support@microsoft-security-check.example</span>
                </div>
                <div className="landing-screenshot-field">
                  <label>Reply-To</label>
                  <span>verify@identity-gateway.example</span>
                </div>
                <div className="landing-screenshot-field">
                  <label>Originating IP</label>
                  <span>185.70.40.18</span>
                </div>
                <div className="landing-screenshot-field">
                  <label>Signals</label>
                  <span>Lookalike sender, URL-bearing lure, analyst-worthy queue score</span>
                </div>
                <div className="landing-screenshot-field">
                  <label>Exports</label>
                  <span>PDF evidence package and IOC CSV available from the same case</span>
                </div>
              </div>
              <div className="landing-screenshot-panel landing-screenshot-rendered">
                <div className="landing-screenshot-rendered-toolbar">
                  <span className="active">Rendered</span>
                  <span>HTML</span>
                  <span>Plaintext</span>
                  <span>Source</span>
                </div>
                <div className="landing-screenshot-message">
                  <p>Hello,</p>
                  <p>
                    Your Microsoft 365 password expires today. Review the account notice and confirm your identity to
                    avoid interruption.
                  </p>
                  <p>
                    We detected unusual login activity on your mailbox and need immediate verification to keep access
                    active.
                  </p>
                  <p>
                    <a href="#void">Review sign-in</a>
                  </p>
                  <p>Microsoft 365 Security Team</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="why-triagent" className="landing-section landing-story-section">
        <div className="landing-section-copy">
          <span className="landing-kicker">Why Triagent</span>
          <h2 className="landing-section-title">Reported phishing is one of the most repetitive security workflows, but most teams still work the case by hand.</h2>
          <p>
            Analysts lose time opening headers, checking URLs, comparing sender context, writing notes, and preserving
            evidence across separate tools. Triagent is designed to tighten that loop without pretending the analyst is
            unnecessary.
          </p>
        </div>
        <div className="landing-story-grid">
          <div className="landing-story-visual">
            <div className="landing-story-card">
              <div className="landing-story-menu">
                <span className="landing-story-chip landing-story-chip-alert">Auto-analysis</span>
                <span>Flag as malicious</span>
                <span>Flag as safe</span>
                <span>Open source</span>
                <span>Copy IOC</span>
              </div>
              <div className="landing-story-code">
                <span>Received-SPF: fail</span>
                <span>ARC-Seal: pass</span>
                <span>Reply-To: external mismatch</span>
                <span>Final URL: identity-gateway.example</span>
              </div>
            </div>
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

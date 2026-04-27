import Image from "next/image";
import Link from "next/link";
import { FormEvent, useState } from "react";

import { createWaitlistLead } from "../lib/api";
import { useAuth } from "../lib/auth-context";

const WORKFLOW_STEPS = [
  {
    title: "Email ingestion",
    copy: "Start from the original reported message through manual upload or the Outlook add-in, preserve the source, and normalize the evidence immediately.",
  },
  {
    title: "Analyst-first prioritization",
    copy: "Triagent sorts reported mail into a likely benign path or an analyst-review path, so only the stronger cases reach the In-tray.",
  },
  {
    title: "Evidence-first console",
    copy: "Uploads preserve the original message and evidence, while the In-tray surfaces the cases that need analyst attention with auth, URLs, attachments, raw source, and notes together.",
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
      "Triagent currently supports reported-email triage, evidence review, analyst resolution, audit history, PDF / IOC export, and intake through manual uploads and the Outlook add-in in a working demo environment.",
  },
  {
    question: "What is the difference between Uploads and In-tray?",
    answer:
      "Uploads is the intake and evidence workspace for reported emails. In-tray is the analyst queue that shows the cases Triagent routes into review after categorization and prioritization.",
  },
  {
    question: "How is this different from a spam filter or SEG?",
    answer:
      "Triagent is not a secure email gateway replacement. It is an analyst workflow for handling user-reported suspicious emails after they reach the mailbox.",
  },
  {
    question: "Who is this for right now?",
    answer:
      "Triagent is built for internal SOC / SecOps teams and MSSPs that repeatedly handle phishing reports and need a tighter investigation and case-close workflow.",
  },
  {
    question: "Is it suitable for MSSPs?",
    answer:
      "Yes. MSSPs face the same repetitive review and evidence-packaging work, often across multiple customer environments, and Triagent is designed to fit that repeatable service workflow.",
  },
  {
    question: "Do you support on-prem deployment?",
    answer:
      "Yes. On-prem and private deployment support are part of the product direction because many regulated teams and MSSPs do not want reported email content and evidence to leave their environment.",
  },
  {
    question: "Is the Outlook add-in part of the product?",
    answer:
      "Yes. Triagent includes an Outlook add-in path for reporting suspicious email into the workflow, alongside manual upload for demo and analyst-driven investigation scenarios.",
  },
  {
    question: "What is automated versus analyst-reviewed?",
    answer:
      "Triagent assists with prioritization, evidence gathering, and packaging. The final disposition and classification stay analyst-controlled.",
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
          <h2 className="landing-section-title">Auto-categorize reported email before analysts dig in.</h2>
          <p>
            Triagent automatically separates low-value reported mail from the cases that deserve analyst attention, so
            analysts start from a tighter queue with the evidence and draft resolution already attached.
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
                width={3080}
                height={1320}
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
          <h2 className="landing-section-title">Triagent fits the reported-email workflow teams already have.</h2>
          <p>
            Start from reported mail, package the evidence, help the analyst decide faster, and close the case cleanly.
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
          <h2 className="landing-section-title">Built for internal SOCs and MSSP teams.</h2>
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
          <span className="landing-kicker">In the demo</span>
          <h2 className="landing-proof-title">See how a reported email becomes a decision.</h2>
          <ul className="landing-list">
            <li>Queue reported emails by analyst priority instead of treating every report as equal.</li>
            <li>Review auth, URLs, attachments, raw source, and analyst notes in the same case workspace.</li>
            <li>Resolve, classify, and export evidence from the same report without switching tools.</li>
          </ul>
        </article>
        <article className="landing-proof-card">
          <span className="landing-kicker">What Triagent is today</span>
          <h2 className="landing-proof-title">Focused reported-email triage for analyst teams.</h2>
          <ul className="landing-list">
            <li>Evidence-first phishing triage, not a full email-security suite.</li>
            <li>Analyst workflow with queueing, assist draft, audit history, and case exports.</li>
            <li>Built for teams that want faster handling of user-reported suspicious email.</li>
          </ul>
        </article>
      </section>

      <section id="faq" className="landing-section">
        <div className="landing-section-copy landing-section-copy-wide">
          <span className="landing-kicker">Frequently asked questions</span>
          <h2 className="landing-section-title">Questions security teams usually ask.</h2>
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
          <h2 className="landing-section-title">Request demo access.</h2>
          <p>Share your work email and a bit of context. Required fields are marked with a star.</p>
        </div>
        <form className="landing-form" onSubmit={onSubmit}>
          <div className="landing-form-grid">
            <div className="landing-form-field">
              <label htmlFor="waitlist-email">Work email *</label>
              <input
                id="waitlist-email"
                className="input"
                type="email"
                value={workEmail}
                onChange={(event) => setWorkEmail(event.target.value)}
                autoComplete="email"
                placeholder="you@company.com"
                required
              />
            </div>
            <div className="landing-form-field">
              <label htmlFor="waitlist-name">Name</label>
              <input
                id="waitlist-name"
                className="input"
                value={name}
                onChange={(event) => setName(event.target.value)}
                autoComplete="name"
                placeholder="Your name"
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
                placeholder="Company"
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
                placeholder="SOC manager, analyst, MSSP lead..."
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

          {error ? <p className="auth-error">{error}</p> : null}
          {success ? <p className="landing-success">{success}</p> : null}

          <div className="landing-form-actions">
            <button className="resolve-button landing-form-submit" type="submit" disabled={submitting}>
              {submitting ? "Joining..." : "Join waitlist"}
            </button>
            <span className="landing-form-note">No spam. We’ll only use this to coordinate access and follow-up.</span>
          </div>
        </form>
      </section>

      <footer className="landing-footer">
        <div className="landing-footer-grid">
          <div className="landing-footer-brand">
            <strong>Triagent</strong>
            <p>Reported-email triage for SOC teams and MSSPs.</p>
          </div>
          <div className="landing-footer-column">
            <p className="landing-footer-label">Product</p>
            <a href="#why-triagent">Why Triagent</a>
            <a href="#how-it-works">How it works</a>
            <a href="#mssps">MSSPs</a>
            <Link href={demoHref}>Try the demo</Link>
          </div>
          <div className="landing-footer-column">
            <p className="landing-footer-label">Contact</p>
            <a href="#waitlist">Join waitlist</a>
            <a href="mailto:alexanderxhuelsmann@gmail.com">alexanderxhuelsmann@gmail.com</a>
            <a href="tel:+4915787351124">+49 157 87351124</a>
          </div>
          <div className="landing-footer-column">
            <p className="landing-footer-label">Legal</p>
            <Link href="/privacy">Privacy</Link>
            <Link href="/imprint">Imprint</Link>
          </div>
        </div>
        <div className="landing-footer-meta">
          <span>Operated by Alexander Huelsmann, Muenster, Germany.</span>
          <span>No company formed yet.</span>
        </div>
      </footer>
    </main>
  );
}

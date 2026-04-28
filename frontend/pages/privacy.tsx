import Link from "next/link";

export default function PrivacyPage() {
  return (
    <main className="legal-page">
      <div className="legal-shell">
        <p className="legal-kicker">Legal</p>
        <h1>Privacy policy</h1>
        <p className="legal-intro">
          This privacy policy explains what personal data is processed when you use the Triagent application.
        </p>

        <section className="legal-section">
          <h2>Controller</h2>
          <p>
            Alexander Huelsmann
            <br />
            Rigaweg 19
            <br />
            48159 Muenster
            <br />
            Germany
            <br />
            Email:{" "}
            <a href="mailto:alexanderxhuelsmann@gmail.com" className="legal-link">
              alexanderxhuelsmann@gmail.com
            </a>
          </p>
        </section>

        <section className="legal-section">
          <h2>What data is processed</h2>
          <ul className="legal-list">
            <li>Account and session data needed to authenticate users and operate the application.</li>
            <li>Basic request and security metadata needed to operate the application, such as IP address and user agent.</li>
            <li>Uploaded phishing-triage data where users intentionally submit messages or related evidence.</li>
          </ul>
        </section>

        <section className="legal-section">
          <h2>Purposes and legal bases</h2>
          <ul className="legal-list">
            <li>
              To provide authenticated access to the application, process submitted triage data, and support operational
              security. Legal basis: Article 6 paragraph 1 letter b GDPR and, where applicable, Article 6 paragraph 1
              letter f GDPR.
            </li>
            <li>
              To maintain security, prevent misuse, troubleshoot issues, and keep audit records. Legal basis: Article 6
              paragraph 1 letter f GDPR.
            </li>
          </ul>
        </section>

        <section className="legal-section">
          <h2>Recipients</h2>
          <p>
            Data is processed by the website operator and may be handled by technical service providers used for hosting,
            storage, and operation of the application where this is necessary to provide the service.
          </p>
        </section>

        <section className="legal-section">
          <h2>Retention</h2>
          <ul className="legal-list">
            <li>Application records are retained only as long as needed for operation, troubleshooting, and agreed usage.</li>
            <li>Security-related logs may be retained where needed for auditability, troubleshooting, and abuse prevention.</li>
          </ul>
        </section>

        <section className="legal-section">
          <h2>Provision of data</h2>
          <p>
            Account and submitted triage data are needed to use the application. Without the required account data,
            authenticated access cannot be provided.
          </p>
        </section>

        <section className="legal-section">
          <h2>Your rights</h2>
          <ul className="legal-list">
            <li>Right of access</li>
            <li>Right to rectification</li>
            <li>Right to erasure</li>
            <li>Right to restriction of processing</li>
            <li>Right to object</li>
            <li>Right to data portability, where applicable</li>
            <li>Right to lodge a complaint with a supervisory authority</li>
          </ul>
          <p>
            To exercise your rights, contact{" "}
            <a href="mailto:alexanderxhuelsmann@gmail.com" className="legal-link">
              alexanderxhuelsmann@gmail.com
            </a>
            .
          </p>
        </section>

        <section className="legal-section">
          <h2>Cookies and tracking</h2>
          <p>
            This site does not use marketing or analytics tracking by default. Technical session handling may be used
            where necessary to operate login access.
          </p>
        </section>

        <div className="legal-actions">
          <Link href="/login" className="legal-link">
            Back to login
          </Link>
          <Link href="/imprint" className="legal-link">
            Imprint
          </Link>
        </div>
      </div>
    </main>
  );
}

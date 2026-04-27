import Link from "next/link";

export default function ImprintPage() {
  return (
    <main className="legal-page">
      <div className="legal-shell">
        <p className="legal-kicker">Legal</p>
        <h1>Imprint</h1>
        <p className="legal-intro">Information according to Section 5 DDG and Section 18 paragraph 2 MStV.</p>

        <section className="legal-section">
          <h2>Responsible for this website</h2>
          <p>
            Alexander Huelsmann
            <br />
            Rigaweg 19
            <br />
            48159 Muenster
            <br />
            Germany
          </p>
        </section>

        <section className="legal-section">
          <h2>Contact</h2>
          <p>
            Email:{" "}
            <a href="mailto:alexanderxhuelsmann@gmail.com" className="legal-link">
              alexanderxhuelsmann@gmail.com
            </a>
            <br />
            Phone:{" "}
            <a href="tel:+4915787351124" className="legal-link">
              +49 157 87351124
            </a>
          </p>
        </section>

        <section className="legal-section">
          <h2>Business information</h2>
          <p>
            No company has been formed yet.
            <br />
            No commercial register entry exists.
            <br />
            No VAT ID is available.
          </p>
        </section>

        <section className="legal-section">
          <h2>Editorial responsibility</h2>
          <p>
            Responsible for editorial content according to Section 18 paragraph 2 MStV:
            <br />
            Alexander Huelsmann, Rigaweg 19, 48159 Muenster, Germany
          </p>
        </section>

        <div className="legal-actions">
          <Link href="/" className="legal-link">
            Back to landing page
          </Link>
          <Link href="/privacy" className="legal-link">
            Privacy policy
          </Link>
        </div>
      </div>
    </main>
  );
}

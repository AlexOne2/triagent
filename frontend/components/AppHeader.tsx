import Link from "next/link";

export default function AppHeader() {
  return (
    <div className="app-header">
      <div className="app-brand">MailSentry</div>
      <div className="app-nav">
        <Link href="/dashboard" className="nav-button">
          Dashboard
        </Link>
        <Link href="/in-tray" className="nav-button">
          In-tray
        </Link>
        <Link href="/reports" className="nav-button primary">
          Uploads
        </Link>
      </div>
    </div>
  );
}

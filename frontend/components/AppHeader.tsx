import Link from "next/link";
import { useRouter } from "next/router";

export default function AppHeader() {
  const router = useRouter();
  const path = router.pathname;

  const isDashboard = path.startsWith("/dashboard");
  const isInTray = path.startsWith("/in-tray");
  const isUploads = path === "/" || path.startsWith("/reports");

  return (
    <div className="app-header">
      <div className="app-brand">MailSentry</div>
      <div className="app-nav">
        <Link href="/dashboard" className={`nav-button ${isDashboard ? "active" : ""}`.trim()}>
          Dashboard
        </Link>
        <Link href="/in-tray" className={`nav-button ${isInTray ? "active" : ""}`.trim()}>
          In-tray
        </Link>
        <Link href="/reports" className={`nav-button ${isUploads ? "active" : ""}`.trim()}>
          Uploads
        </Link>
      </div>
    </div>
  );
}

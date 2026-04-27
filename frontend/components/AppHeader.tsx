import Link from "next/link";
import { useRouter } from "next/router";
import { useAuth } from "../lib/auth-context";

export default function AppHeader() {
  const router = useRouter();
  const path = router.pathname;
  const { hasPermission, logout, roles, user } = useAuth();

  const isDashboard = path.startsWith("/dashboard");
  const isInTray = path.startsWith("/in-tray");
  const isUploads = path === "/" || path.startsWith("/reports");
  const isSettings = path.startsWith("/settings") || path.startsWith("/admin");
  const isDemoUser = roles.includes("DEMO");

  const canReadReports = hasPermission("reports.read");
  const canReadDashboard = hasPermission("dashboard.read");
  const canAdminUsers =
    hasPermission("admin.users.read") || hasPermission("admin.api_keys.manage") || hasPermission("audit.read");

  return (
    <div className="app-header">
      <div className="app-brand">Triagent</div>
      <div className="app-nav">
        {canReadDashboard ? (
          <Link href="/dashboard" className={`nav-button ${isDashboard ? "active" : ""}`.trim()}>
            Dashboard
          </Link>
        ) : null}
        {canReadReports ? (
          <Link href="/in-tray" className={`nav-button ${isInTray ? "active" : ""}`.trim()}>
            In-tray
          </Link>
        ) : null}
        {canReadReports ? (
          <Link href="/reports" className={`nav-button ${isUploads ? "active" : ""}`.trim()}>
            Uploads
          </Link>
        ) : null}
        {canAdminUsers ? (
          <Link href="/settings" className={`nav-button ${isSettings ? "active" : ""}`.trim()}>
            Settings
          </Link>
        ) : null}
        {isDemoUser ? (
          <Link href="/#waitlist" className="nav-button">
            Join waitlist
          </Link>
        ) : null}
        <button className="nav-button" type="button" onClick={() => void logout()}>
          Logout{user?.username ? ` (${user.username})` : ""}
        </button>
      </div>
    </div>
  );
}

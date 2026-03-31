import Link from "next/link";
import { useRouter } from "next/router";
import { useAuth } from "../lib/auth-context";

export default function AppHeader() {
  const router = useRouter();
  const path = router.pathname;
  const { hasPermission, logout, user } = useAuth();

  const isDashboard = path.startsWith("/dashboard");
  const isInTray = path.startsWith("/in-tray");
  const isCampaigns = path.startsWith("/campaigns");
  const isUploads = path === "/" || path.startsWith("/reports");
  const isAdmin = path.startsWith("/admin");

  const canReadReports = hasPermission("reports.read");
  const canReadDashboard = hasPermission("dashboard.read");
  const canReadCampaigns = hasPermission("campaigns.read");
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
        {canReadCampaigns ? (
          <Link href="/campaigns" className={`nav-button ${isCampaigns ? "active" : ""}`.trim()}>
            Campaigns
          </Link>
        ) : null}
        {canReadReports ? (
          <Link href="/reports" className={`nav-button ${isUploads ? "active" : ""}`.trim()}>
            Uploads
          </Link>
        ) : null}
        {canAdminUsers ? (
          <Link href="/admin/users" className={`nav-button ${isAdmin ? "active" : ""}`.trim()}>
            Admin
          </Link>
        ) : null}
        <button className="nav-button" type="button" onClick={() => void logout()}>
          Logout{user?.username ? ` (${user.username})` : ""}
        </button>
      </div>
    </div>
  );
}

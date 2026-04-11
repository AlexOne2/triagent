import Link from "next/link";
import { useRouter } from "next/router";
import { useAuth } from "../lib/auth-context";

export default function SettingsNav() {
  const router = useRouter();
  const { hasPermission } = useAuth();

  const canUsers = hasPermission("admin.users.read");
  const canApiKeys = hasPermission("admin.api_keys.manage");
  const canAudit = hasPermission("audit.read");
  const isUsers = router.pathname.startsWith("/settings/users") || router.pathname.startsWith("/admin/users");
  const isApiKeys = router.pathname.startsWith("/settings/api-keys") || router.pathname.startsWith("/admin/api-keys");
  const isAudit = router.pathname.startsWith("/settings/audit") || router.pathname.startsWith("/admin/audit");

  return (
    <aside className="settings-sidebar">
      <div className="settings-sidebar-head">
        <strong>Settings</strong>
        <span>Workspace configuration</span>
      </div>
      <nav className="settings-sidebar-nav" aria-label="Settings navigation">
        {canUsers ? (
          <Link href="/settings/users" className={`settings-side-link ${isUsers ? "active" : ""}`.trim()}>
            Users &amp; Access
          </Link>
        ) : null}
        {canApiKeys ? (
          <Link href="/settings/api-keys" className={`settings-side-link ${isApiKeys ? "active" : ""}`.trim()}>
            API Keys
          </Link>
        ) : null}
        {canAudit ? (
          <Link href="/settings/audit" className={`settings-side-link ${isAudit ? "active" : ""}`.trim()}>
            Audit Log
          </Link>
        ) : null}
      </nav>
    </aside>
  );
}

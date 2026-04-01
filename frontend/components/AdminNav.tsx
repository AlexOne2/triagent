import Link from "next/link";
import { useRouter } from "next/router";
import { useAuth } from "../lib/auth-context";

export default function AdminNav() {
  const router = useRouter();
  const { hasPermission } = useAuth();

  const canUsers = hasPermission("admin.users.read");
  const canApiKeys = hasPermission("admin.api_keys.manage");
  const canAudit = hasPermission("audit.read");

  const isUsers = router.pathname.startsWith("/admin/users");
  const isApiKeys = router.pathname.startsWith("/admin/api-keys");
  const isAudit = router.pathname.startsWith("/admin/audit");

  return (
    <div className="admin-subnav">
      {canUsers ? (
        <Link href="/admin/users" className={`tab ${isUsers ? "active" : ""}`.trim()}>
          Users
        </Link>
      ) : null}
      {canApiKeys ? (
        <Link href="/admin/api-keys" className={`tab ${isApiKeys ? "active" : ""}`.trim()}>
          API Keys
        </Link>
      ) : null}
      {canAudit ? (
        <Link href="/admin/audit" className={`tab ${isAudit ? "active" : ""}`.trim()}>
          Audit
        </Link>
      ) : null}
    </div>
  );
}

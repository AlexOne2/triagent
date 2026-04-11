import { FormEvent, useEffect, useMemo, useState } from "react";
import SettingsLayout from "../../components/SettingsLayout";
import { AdminRoleOut, AdminUserOut, createUser, fetchRoles, fetchUsers, replaceUserRoles, updateUser } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

type UserDraft = {
  email: string;
  password: string;
  isActive: boolean;
  roleKeys: string[];
};

export default function SettingsUsersPage() {
  const { hasPermission } = useAuth();
  const canRead = hasPermission("admin.users.read");
  const canWrite = hasPermission("admin.users.write");

  const [users, setUsers] = useState<AdminUserOut[]>([]);
  const [roles, setRoles] = useState<AdminRoleOut[]>([]);
  const [drafts, setDrafts] = useState<Record<number, UserDraft>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [savingUserId, setSavingUserId] = useState<number | null>(null);

  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRoleKeys, setNewRoleKeys] = useState<string[]>(["ANALYST"]);
  const [newIsActive, setNewIsActive] = useState(true);

  const roleKeys = useMemo(() => roles.map((role) => role.key), [roles]);

  const load = async () => {
    if (!canRead) return;
    setLoading(true);
    setError(null);
    try {
      const [usersData, rolesData] = await Promise.all([fetchUsers(), fetchRoles()]);
      setUsers(usersData);
      setRoles(rolesData);
      const nextDrafts: Record<number, UserDraft> = {};
      usersData.forEach((user) => {
        nextDrafts[user.id] = {
          email: user.email || "",
          password: "",
          isActive: user.is_active,
          roleKeys: user.role_keys,
        };
      });
      setDrafts(nextDrafts);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load users");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [canRead]);

  const toggleRole = (selected: string[], roleKey: string): string[] => {
    if (selected.includes(roleKey)) {
      return selected.filter((key) => key !== roleKey);
    }
    return [...selected, roleKey];
  };

  const submitCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (!canWrite) return;
    setSavingUserId(-1);
    setError(null);
    try {
      await createUser({
        username: newUsername,
        email: newEmail || null,
        password: newPassword,
        role_keys: newRoleKeys,
        is_active: newIsActive,
      });
      setNewUsername("");
      setNewEmail("");
      setNewPassword("");
      setNewRoleKeys(["ANALYST"]);
      setNewIsActive(true);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    } finally {
      setSavingUserId(null);
    }
  };

  const saveProfile = async (user: AdminUserOut) => {
    const draft = drafts[user.id];
    if (!draft || !canWrite) return;
    setSavingUserId(user.id);
    setError(null);
    try {
      await updateUser(user.id, {
        email: draft.email || null,
        password: draft.password || undefined,
        is_active: draft.isActive,
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update user");
    } finally {
      setSavingUserId(null);
    }
  };

  const saveRoles = async (user: AdminUserOut) => {
    const draft = drafts[user.id];
    if (!draft || !canWrite) return;
    setSavingUserId(user.id);
    setError(null);
    try {
      await replaceUserRoles(user.id, draft.roleKeys);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update roles");
    } finally {
      setSavingUserId(null);
    }
  };

  if (!canRead) {
    return (
      <main className="full">
        <h1>Settings - Users &amp; Access</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  return (
    <SettingsLayout title="Users &amp; Access" description="Manage local users and role assignments.">
      {error ? <p className="auth-error">{error}</p> : null}

      {canWrite ? (
        <section className="card" style={{ marginBottom: 16 }}>
          <h2>Create User</h2>
          <form className="admin-form" onSubmit={submitCreate}>
            <input className="input" placeholder="Username" value={newUsername} onChange={(event) => setNewUsername(event.target.value)} required />
            <input className="input" placeholder="Email (optional)" value={newEmail} onChange={(event) => setNewEmail(event.target.value)} />
            <input className="input" type="password" placeholder="Password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required />
            <label className="admin-checkbox">
              <input type="checkbox" checked={newIsActive} onChange={(event) => setNewIsActive(event.target.checked)} />
              Active
            </label>
            <div className="admin-role-picker">
              {roleKeys.map((roleKey) => (
                <label key={roleKey} className="admin-checkbox">
                  <input type="checkbox" checked={newRoleKeys.includes(roleKey)} onChange={() => setNewRoleKeys((current) => toggleRole(current, roleKey))} />
                  {roleKey}
                </label>
              ))}
            </div>
            <button className="resolve-button" type="submit" disabled={savingUserId === -1}>
              {savingUserId === -1 ? "Creating..." : "Create User"}
            </button>
          </form>
        </section>
      ) : null}

      <section className="card">
        <h2>Existing Users</h2>
        {loading ? <p>Loading users...</p> : null}
        {!loading && users.length === 0 ? <p>No users found.</p> : null}

        {users.map((user) => {
          const draft = drafts[user.id];
          if (!draft) return null;
          return (
            <div key={user.id} className="admin-user-row">
              <div className="admin-user-head">
                <strong>{user.username}</strong>
                <span>{user.email || "-"}</span>
              </div>

              <div className="admin-user-grid">
                <input
                  className="input"
                  value={draft.email}
                  placeholder="Email"
                  onChange={(event) => setDrafts((current) => ({ ...current, [user.id]: { ...draft, email: event.target.value } }))}
                  disabled={!canWrite}
                />
                <input
                  className="input"
                  type="password"
                  value={draft.password}
                  placeholder="New password (optional)"
                  onChange={(event) => setDrafts((current) => ({ ...current, [user.id]: { ...draft, password: event.target.value } }))}
                  disabled={!canWrite}
                />
                <label className="admin-checkbox">
                  <input
                    type="checkbox"
                    checked={draft.isActive}
                    onChange={(event) => setDrafts((current) => ({ ...current, [user.id]: { ...draft, isActive: event.target.checked } }))}
                    disabled={!canWrite}
                  />
                  Active
                </label>
              </div>

              <div className="admin-role-picker">
                {roleKeys.map((roleKey) => (
                  <label key={`${user.id}-${roleKey}`} className="admin-checkbox">
                    <input
                      type="checkbox"
                      checked={draft.roleKeys.includes(roleKey)}
                      onChange={() =>
                        setDrafts((current) => ({ ...current, [user.id]: { ...draft, roleKeys: toggleRole(draft.roleKeys, roleKey) } }))
                      }
                      disabled={!canWrite}
                    />
                    {roleKey}
                  </label>
                ))}
              </div>

              {canWrite ? (
                <div className="admin-actions">
                  <button className="resolve-button secondary" type="button" onClick={() => void saveProfile(user)} disabled={savingUserId === user.id}>
                    {savingUserId === user.id ? "Saving..." : "Save Profile"}
                  </button>
                  <button className="tab" type="button" onClick={() => void saveRoles(user)} disabled={savingUserId === user.id}>
                    {savingUserId === user.id ? "Saving..." : "Save Roles"}
                  </button>
                </div>
              ) : null}
            </div>
          );
        })}
      </section>
    </SettingsLayout>
  );
}

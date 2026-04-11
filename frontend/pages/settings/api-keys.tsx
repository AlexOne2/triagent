import { FormEvent, useEffect, useState } from "react";
import SettingsLayout from "../../components/SettingsLayout";
import { AdminApiKeyOut, createApiKey, fetchApiKeys, revokeApiKey } from "../../lib/api";
import { useAuth } from "../../lib/auth-context";

export default function SettingsApiKeysPage() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("admin.api_keys.manage");

  const [keys, setKeys] = useState<AdminApiKeyOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [newKeyPlaintext, setNewKeyPlaintext] = useState<string | null>(null);

  const load = async () => {
    if (!canManage) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchApiKeys();
      setKeys(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load API keys");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [canManage]);

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    if (!canManage || creating) return;
    setCreating(true);
    setError(null);
    setNewKeyPlaintext(null);
    try {
      const created = await createApiKey({
        name,
        role_key: "INGESTOR",
        expires_at: expiresAt ? new Date(`${expiresAt}T23:59:59.999Z`).toISOString() : null,
      });
      setName("");
      setExpiresAt("");
      setNewKeyPlaintext(created.api_key || null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create API key");
    } finally {
      setCreating(false);
    }
  };

  const onRevoke = async (id: number) => {
    if (!canManage) return;
    setError(null);
    try {
      await revokeApiKey(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke key");
    }
  };

  if (!canManage) {
    return (
      <main className="full">
        <h1>Settings - API Keys</h1>
        <p>Insufficient permissions.</p>
      </main>
    );
  }

  return (
    <SettingsLayout title="API Keys" description="Create and revoke ingestion API keys.">
      {error ? <p className="auth-error">{error}</p> : null}

      <section className="card" style={{ marginBottom: 16 }}>
        <h2>Create API Key</h2>
        <form className="admin-form" onSubmit={onCreate}>
          <input className="input" placeholder="Key name" value={name} onChange={(event) => setName(event.target.value)} required />
          <input className="input" type="date" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
          <button className="resolve-button" type="submit" disabled={creating}>
            {creating ? "Creating..." : "Create INGESTOR Key"}
          </button>
        </form>

        {newKeyPlaintext ? (
          <div className="admin-secret-box">
            <strong>Copy this API key now (shown once):</strong>
            <code>{newKeyPlaintext}</code>
          </div>
        ) : null}
      </section>

      <section className="card">
        <h2>Existing Keys</h2>
        {loading ? <p>Loading keys...</p> : null}
        {!loading && keys.length === 0 ? <p>No keys found.</p> : null}

        {keys.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Prefix</th>
                <th>Role</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Revoked</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id}>
                  <td>{key.name}</td>
                  <td>{key.key_prefix}</td>
                  <td>{key.role_key}</td>
                  <td>{new Date(key.created_at).toLocaleString()}</td>
                  <td>{key.expires_at ? new Date(key.expires_at).toLocaleString() : "-"}</td>
                  <td>{key.revoked_at ? new Date(key.revoked_at).toLocaleString() : "No"}</td>
                  <td>
                    {!key.revoked_at ? (
                      <button className="tab" type="button" onClick={() => void onRevoke(key.id)}>
                        Revoke
                      </button>
                    ) : (
                      "-"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </section>
    </SettingsLayout>
  );
}

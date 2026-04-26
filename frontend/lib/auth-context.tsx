import { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { authDemoLogin, authLogin, authLogout, authMe, AuthUser, setUnauthorizedHandler } from "./api";
import { clearAccessToken, getAccessToken, setAccessToken } from "./auth-storage";

type AuthContextValue = {
  user: AuthUser | null;
  roles: string[];
  permissions: string[];
  loading: boolean;
  isAuthenticated: boolean;
  hasPermission: (permission: string) => boolean;
  login: (username: string, password: string) => Promise<void>;
  loginDemo: () => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [roles, setRoles] = useState<string[]>([]);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  const resetAuthState = useCallback(() => {
    clearAccessToken();
    setUser(null);
    setRoles([]);
    setPermissions([]);
  }, []);

  const loadCurrentUser = useCallback(async () => {
    const token = getAccessToken();
    if (!token) {
      setLoading(false);
      return;
    }

    try {
      const me = await authMe();
      setUser(me.user);
      setRoles(me.roles || []);
      setPermissions(me.permissions || []);
    } catch {
      resetAuthState();
    } finally {
      setLoading(false);
    }
  }, [resetAuthState]);

  useEffect(() => {
    void loadCurrentUser();
  }, [loadCurrentUser]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      resetAuthState();
    });
    return () => setUnauthorizedHandler(null);
  }, [resetAuthState]);

  const login = useCallback(async (username: string, password: string) => {
    const result = await authLogin({ username, password });
    setAccessToken(result.access_token, result.expires_at);
    setUser(result.user);
    setRoles(result.roles || []);
    setPermissions(result.permissions || []);
  }, []);

  const loginDemo = useCallback(async () => {
    const result = await authDemoLogin();
    setAccessToken(result.access_token, result.expires_at);
    setUser(result.user);
    setRoles(result.roles || []);
    setPermissions(result.permissions || []);
  }, []);

  const logout = useCallback(async () => {
    try {
      if (getAccessToken()) {
        await authLogout();
      }
    } catch {
      // Best-effort logout; local state still needs clearing.
    } finally {
      resetAuthState();
    }
  }, [resetAuthState]);

  const hasPermission = useCallback(
    (permission: string) => permissions.includes(permission),
    [permissions]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      roles,
      permissions,
      loading,
      isAuthenticated: Boolean(user),
      hasPermission,
      login,
      loginDemo,
      logout,
    }),
    [user, roles, permissions, loading, hasPermission, login, loginDemo, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

const ACCESS_TOKEN_KEY = "triagent.access_token";
const EXPIRES_AT_KEY = "triagent.access_token_expires_at";

function canUseStorage(): boolean {
  return typeof window !== "undefined" && typeof window.sessionStorage !== "undefined";
}

export function getAccessToken(): string | null {
  if (!canUseStorage()) {
    return null;
  }
  return window.sessionStorage.getItem(ACCESS_TOKEN_KEY);
}

export function setAccessToken(token: string, expiresAt?: string | null): void {
  if (!canUseStorage()) {
    return;
  }
  window.sessionStorage.setItem(ACCESS_TOKEN_KEY, token);
  if (expiresAt) {
    window.sessionStorage.setItem(EXPIRES_AT_KEY, expiresAt);
  } else {
    window.sessionStorage.removeItem(EXPIRES_AT_KEY);
  }
}

export function clearAccessToken(): void {
  if (!canUseStorage()) {
    return;
  }
  window.sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  window.sessionStorage.removeItem(EXPIRES_AT_KEY);
}

export function getAccessTokenExpiry(): string | null {
  if (!canUseStorage()) {
    return null;
  }
  return window.sessionStorage.getItem(EXPIRES_AT_KEY);
}

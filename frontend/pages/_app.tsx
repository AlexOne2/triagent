import type { AppProps } from "next/app";
import { useEffect } from "react";
import { useRouter } from "next/router";

import AppHeader from "../components/AppHeader";
import { AuthProvider, useAuth } from "../lib/auth-context";
import "../styles/globals.css";

function AppContent({ Component, pageProps }: AppProps) {
  const router = useRouter();
  const { loading, isAuthenticated } = useAuth();

  const isLoginPage = router.pathname === "/login";
  const isLegalPage = router.pathname === "/imprint" || router.pathname === "/privacy";
  const isPublicRoute = router.pathname === "/" || isLoginPage || isLegalPage;

  useEffect(() => {
    if (loading) return;
    if (!isAuthenticated && !isPublicRoute) {
      router.replace("/login");
    }
    if (isAuthenticated && isLoginPage) {
      router.replace("/reports");
    }
  }, [loading, isAuthenticated, isLoginPage, isPublicRoute, router]);

  if (loading && !isPublicRoute) {
    return (
      <main className="full">
        <p>Loading...</p>
      </main>
    );
  }

  if (isAuthenticated && isLoginPage) {
    return null;
  }

  if (!isAuthenticated && !isPublicRoute) {
    return null;
  }

  if (isPublicRoute) {
    return <Component {...pageProps} />;
  }

  return (
    <div className="app-shell">
      <AppHeader />
      <Component {...pageProps} />
    </div>
  );
}

export default function App(props: AppProps) {
  return (
    <AuthProvider>
      <AppContent {...props} />
    </AuthProvider>
  );
}

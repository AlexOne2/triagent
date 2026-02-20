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

  useEffect(() => {
    if (loading) return;
    if (!isAuthenticated && !isLoginPage) {
      router.replace("/login");
    }
    if (isAuthenticated && isLoginPage) {
      router.replace("/reports");
    }
  }, [loading, isAuthenticated, isLoginPage, router]);

  if (loading) {
    return (
      <main className="full">
        <p>Loading...</p>
      </main>
    );
  }

  if (!isAuthenticated && !isLoginPage) {
    return null;
  }

  return (
    <>
      {!isLoginPage ? <AppHeader /> : null}
      <Component {...pageProps} />
    </>
  );
}

export default function App(props: AppProps) {
  return (
    <AuthProvider>
      <AppContent {...props} />
    </AuthProvider>
  );
}

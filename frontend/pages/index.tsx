import { useEffect } from "react";
import { useRouter } from "next/router";
import { useAuth } from "../lib/auth-context";

export default function Home() {
  const router = useRouter();
  const { hasPermission } = useAuth();

  useEffect(() => {
    if (hasPermission("reports.read")) {
      router.replace("/reports");
      return;
    }
    if (hasPermission("dashboard.read")) {
      router.replace("/dashboard");
      return;
    }
    router.replace("/login");
  }, [router, hasPermission]);

  return null;
}

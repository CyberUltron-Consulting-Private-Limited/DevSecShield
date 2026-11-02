"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { makeQueryClient } from "@/utils/query_client"
import { checkSuperuser } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [status, setStatus] = useState<"checking" | "allowed" | "denied">("checking");
  const [queryClient] = useState(() => makeQueryClient());

  useEffect(() => {
    const verify = async () => {
      if (typeof window === "undefined") return;
      const token = localStorage.getItem("access_token");
      if (!token || token === "") {
        router.push("/login");
        return;
      }
      try {
        await checkSuperuser();
        setStatus("allowed");
      } catch (error) {
        setStatus("denied");
        showErrorToast(error, "Access denied. Superuser privileges required.");
        router.push("/home");
      }
    };
    verify();
  }, [router]);

  if (status === "checking") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-10 w-10 animate-spin text-blue-500" />
          <p className="text-sm text-zinc-400">Verifying admin access...</p>
        </div>
      </div>
    );
  }

  if (status === "denied") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950">
        <div className="flex flex-col items-center gap-4">
          <p className="text-zinc-400">Access denied. Redirecting...</p>
          <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
        </div>
      </div>
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
}

"use client";

import { usePathname } from "next/navigation";

export default function GuardrailsIntegrationDashboardPage() {
  const pathname = usePathname();
  const integration_id = pathname.split('/').pop() || '';

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
              Guardrails Integration Dashboard
            </h1>
            <p className="text-zinc-600 dark:text-zinc-400">
              Integration ID: {integration_id}
            </p>
          </div>
          <div className="text-center py-12">
            <p className="text-zinc-600 dark:text-zinc-400">
              Dashboard content will be implemented here.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}


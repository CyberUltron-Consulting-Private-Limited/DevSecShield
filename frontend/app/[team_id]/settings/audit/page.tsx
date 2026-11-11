"use client";

import { useParams } from "next/navigation";

import AuditLogPage from "@/components/rbac/AuditLogPage";

export default function Page() {
  const params = useParams();
  const teamId = Number(params?.team_id);
  if (!Number.isFinite(teamId) || teamId <= 0) {
    return <div className="p-8 text-zinc-600 dark:text-zinc-400">Team not found.</div>;
  }
  return <AuditLogPage teamId={teamId} />;
}

"use client";

/**
 * F4 RBAC: the signed-in person's role in the current team, for every page under app/[team_id].
 *
 * <TeamAccessProvider> (in app/[team_id]/layout.tsx) reads GET /team/{id} (the same React Query key as the settings
 * page), <ReadOnlyBanner> tells a viewer why nothing can be changed, and <ReadOnlyGate permission="..."> disables
 * every control inside it (a disabled <fieldset>) when the role lacks the permission. The API refuses the same
 * actions with 403 whatever the UI shows.
 */
import { createContext, useContext, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Eye } from "lucide-react";

import api from "@/utils/interceptors";
import { READ_ONLY_TEXT, READ_ONLY_TITLE, accessFrom, can, isReadOnly, roleLabel, type TeamAccess } from "@/utils/rbac";

type AccessState = { access: TeamAccess | null; loading: boolean };

const TeamAccessContext = createContext<AccessState>({ access: null, loading: false });

async function fetchTeam(teamId: string) {
  const response = await api.get(`/team/${teamId}`);
  return response.data;
}

export function TeamAccessProvider({ teamId, children }: { teamId: string | undefined; children: ReactNode }) {
  // Same key as the settings page (["team-details", team_id]), so both share one request and one cache entry.
  // No toast here: a page that cannot read the team shows its own error.
  const query = useQuery({
    queryKey: ["team-details", teamId],
    queryFn: () => fetchTeam(teamId as string),
    enabled: !!teamId,
    retry: false,
    staleTime: 30_000,
  });
  const access = query.data ? accessFrom(query.data) : null;
  return <TeamAccessContext.Provider value={{ access, loading: query.isLoading }}>{children}</TeamAccessContext.Provider>;
}

export function useTeamAccess(): AccessState & { can: (permission: string) => boolean; readOnly: boolean } {
  const state = useContext(TeamAccessContext);
  return {
    ...state,
    // While loading (or outside a team), allow: the server decides, and a flash of disabled controls is worse.
    can: (permission: string) => (state.access ? can(state.access, permission) : true),
    readOnly: isReadOnly(state.access),
  };
}

export function ReadOnlyBanner() {
  const { access, readOnly } = useTeamAccess();
  if (!readOnly) return null;
  return (
    <div
      role="status"
      data-testid="read-only-banner"
      className="flex items-start gap-2 border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-200"
    >
      <Eye className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <p>
        <strong className="font-medium">{READ_ONLY_TITLE}</strong>{" "}
        <span className="sr-only">(role: {roleLabel(access?.role)})</span>
        <span className="text-amber-100/80">{READ_ONLY_TEXT}</span>
      </p>
    </div>
  );
}

/**
 * Disables every form control inside when the role lacks `permission` (a disabled <fieldset> also disables its
 * buttons, so nothing inside can be submitted), and says why. Links stay usable (reading is allowed).
 */
export function ReadOnlyGate({ permission, children, className }: { permission: string; children: ReactNode; className?: string }) {
  const { can: allowed, access } = useTeamAccess();
  if (allowed(permission)) return <>{children}</>;
  return (
    <fieldset
      disabled
      aria-disabled="true"
      data-testid="read-only-gate"
      data-permission={permission}
      title={`Your role (${roleLabel(access?.role)}) cannot do this`}
      className={`m-0 min-w-0 border-0 p-0 opacity-60 ${className ?? ""}`}
    >
      {children}
    </fieldset>
  );
}

/** Renders `children` only when the role holds `permission` (otherwise `fallback`). */
export function IfAllowed({ permission, children, fallback = null }: { permission: string; children: ReactNode; fallback?: ReactNode }) {
  const { can: allowed } = useTeamAccess();
  return <>{allowed(permission) ? children : fallback}</>;
}

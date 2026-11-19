"use client";

/**
 * Settings > Report branding (plan §5, §7): the team's client logo, drawn next to the ZeroShield logo on the cover and
 * in every page header of the team's PDF reports. Admins (team.branding.manage) upload, replace or remove it; everyone
 * else sees the same preview, read-only.
 *
 * Its own queries: ["team-branding", team] for the metadata and ["team-logo", team, sha256] for the image (a new
 * logo has a new key). It never touches ["team-details", team]: invalidating that query refills the settings form
 * above (the page's effect on `team`) and wipes the name and Jira fields being edited.
 */
import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ImageUp, Loader2, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { InfoTip } from "@/components/ui/info-tip";
import { ConfirmDialog } from "@/components/cbom/sources/shared";
import { useTeamAccess } from "@/components/rbac/team-access";
import { cn } from "@/lib/utils";
import { deleteTeamLogo, getTeamBranding, getTeamLogo, putTeamLogo, type TeamBranding } from "@/utils/backend_api";
import { formatDateIst } from "@/utils/datetime";
import { showErrorToast } from "@/utils/error-handler";
import { can } from "@/utils/rbac";
import { LOGO_ACCEPT, checkLogoFile } from "@/utils/teamBranding";
import { toast } from "@/utils/toast";

export const brandingKey = (teamId: string) => ["team-branding", teamId] as const;
export const logoKey = (teamId: string, sha256: string | null) => ["team-logo", teamId, sha256] as const;

const NO_LOGO: TeamBranding = { logo_set: false, sha256: null, width: null, height: null, tone: null, bytes: null, updated_at: null };

/** The stored logo as an <img>; its object URL is made for this blob and revoked when the blob changes or the image
 * goes away. */
function LogoImage({ blob, className, testId }: { blob: Blob; className?: string; testId?: string }) {
  const ref = useRef<HTMLImageElement>(null);
  useEffect(() => {
    const url = URL.createObjectURL(blob);
    if (ref.current) ref.current.src = url;
    return () => URL.revokeObjectURL(url);
  }, [blob]);
  // eslint-disable-next-line @next/next/no-img-element -- a blob: URL of the team's own logo, not an optimisable asset
  return <img ref={ref} alt="Team logo" className={className} data-testid={testId} />;
}

export function ReportBrandingCard({ teamId }: { teamId: string }) {
  const queryClient = useQueryClient();
  const { access } = useTeamAccess();
  const canManage = can(access, "team.branding.manage");
  const input = useRef<HTMLInputElement>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const branding = useQuery({ queryKey: brandingKey(teamId), queryFn: () => getTeamBranding(teamId), enabled: !!teamId, retry: false });
  const info = branding.data ?? NO_LOGO;
  const sha = info.logo_set ? info.sha256 : null;
  const logo = useQuery({
    queryKey: logoKey(teamId, sha),
    queryFn: () => getTeamLogo(teamId),
    enabled: !!sha,
    staleTime: Infinity, // keyed by the image's sha256: the same key is the same image
    retry: false,
  });
  const blob = sha ? logo.data ?? null : null;

  const upload = useMutation({
    mutationFn: (file: File) => putTeamLogo(teamId, file),
    onSuccess: (data) => {
      queryClient.setQueryData(brandingKey(teamId), data);
      toast.success("Team logo saved: it appears on the team's next PDF reports");
    },
    onError: (error) => showErrorToast(error, "The logo was not saved"),
  });
  const remove = useMutation({
    mutationFn: () => deleteTeamLogo(teamId),
    onSuccess: () => {
      queryClient.setQueryData(brandingKey(teamId), NO_LOGO);
      queryClient.removeQueries({ queryKey: ["team-logo", teamId] });
      setConfirmRemove(false);
      toast.success("Team logo removed");
    },
    onError: (error) => showErrorToast(error, "The logo was not removed"),
  });

  const choose = async (file: File | undefined) => {
    if (input.current) input.current.value = ""; // choosing the same file again still fires
    if (!file) return;
    const checked = await checkLogoFile(file);
    if (checked.error !== null) {
      setProblem(checked.error);
      return;
    }
    setProblem(null);
    upload.mutate(file);
  };

  const light = info.tone === "light";
  const busy = upload.isPending || remove.isPending;
  const meta = info.logo_set
    ? [info.width && info.height ? `${info.width} × ${info.height} px` : null, info.bytes != null ? `${Math.max(1, Math.round(info.bytes / 1024))} KB` : null,
       info.updated_at ? `updated ${formatDateIst(info.updated_at)}` : null].filter(Boolean).join(" · ")
    : "";

  return (
    <section className="pb-6 mb-6 border-b border-border" data-testid="report-branding">
      <h2 className="text-lg font-medium flex items-center gap-1">Report branding <InfoTip id="settings.branding" /></h2>
      <p className="text-sm text-muted-foreground mb-4 mt-1">
        Your client&apos;s logo next to the ZeroShield logo on the cover and in every page header of this team&apos;s PDF reports.
      </p>

      <p className="text-sm font-medium mb-2 flex items-center gap-1">Preview <InfoTip id="settings.branding.preview" /></p>
      <div className="grid gap-3 md:grid-cols-2" data-testid="branding-preview">
        {/* the page header: navy bar, ZeroShield text, the client logo (on a white chip unless it is light) */}
        <div className="rounded-md overflow-hidden border border-border">
          <div className="flex items-center gap-3 bg-[#0b1f3a] px-3 py-2 min-h-11">
            <span className="text-xs font-bold tracking-widest text-white">ZERO SHIELD</span>
            {blob ? (
              <span className={cn("inline-flex items-center rounded px-1.5 py-0.5", !light && "bg-white")} data-testid="branding-header-chip" data-chip={light ? "none" : "white"}>
                <LogoImage blob={blob} className="h-5 max-w-[120px] object-contain" testId="branding-header-logo" />
              </span>
            ) : (
              <span className="text-[11px] text-white/50">{info.logo_set ? "Loading…" : "No client logo"}</span>
            )}
            <span className="ml-auto text-[10px] font-semibold tracking-wider text-white/80">CONFIDENTIAL</span>
          </div>
          <p className="px-3 py-1.5 text-[11px] text-muted-foreground">Page header</p>
        </div>
        {/* the cover: white masthead, the logo in the right column with "Prepared for" under it */}
        <div className="rounded-md overflow-hidden border border-border">
          <div className="flex items-start justify-between gap-3 bg-white px-3 py-3 min-h-[5.5rem]">
            <div className="min-w-0">
              <p className="text-xs font-bold tracking-widest text-[#0b1f3a]">ZERO SHIELD</p>
              <p className="mt-1 text-[11px] text-zinc-600">Security assessment report</p>
            </div>
            <div className="flex flex-col items-end gap-1 shrink-0">
              {blob ? (
                <span className={cn("inline-flex items-center rounded px-1.5 py-1", light && "bg-[#0b1f3a]")} data-testid="branding-cover-chip" data-chip={light ? "navy" : "none"}>
                  <LogoImage blob={blob} className="h-9 max-w-[150px] object-contain" testId="branding-cover-logo" />
                </span>
              ) : (
                <span className="h-9" />
              )}
              <span className="text-[11px] text-zinc-600">Prepared for <span className="italic">your client</span></span>
            </div>
          </div>
          <p className="px-3 py-1.5 text-[11px] text-muted-foreground">Cover</p>
        </div>
      </div>
      {light && (
        <p className="mt-2 text-xs text-amber-600 dark:text-amber-400" data-testid="branding-contrast-hint">
          This logo is light: it is drawn without a chip on the navy header and on a navy chip on the white cover. Check that it stays readable, or upload a darker version.
        </p>
      )}
      {meta && <p className="mt-2 text-xs text-muted-foreground" data-testid="branding-meta">{meta}</p>}
      {branding.isError && <p className="mt-2 text-xs text-red-500">The logo settings could not be read. Reload the page to try again.</p>}

      {canManage ? (
        <div className="mt-4 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={input}
              type="file"
              accept={LOGO_ACCEPT}
              className="hidden"
              data-testid="branding-file"
              onChange={(e) => void choose(e.target.files?.[0])}
            />
            <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={busy} onClick={() => input.current?.click()} data-testid="branding-upload">
              {upload.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <ImageUp className="h-4 w-4 mr-2" />}
              {info.logo_set ? "Replace logo" : "Upload logo"}
            </Button>
            <InfoTip id="settings.branding.logo" />
            {info.logo_set && (
              <Button variant="outline" className="cursor-pointer" disabled={busy} onClick={() => setConfirmRemove(true)} data-testid="branding-remove">
                <Trash2 className="h-4 w-4 mr-2" /> Remove
              </Button>
            )}
          </div>
          <p className="text-xs text-muted-foreground">PNG, JPEG or WebP, up to 2 MB. A wide logo on a transparent background works best.</p>
          {problem && <p className="text-xs text-red-500" role="alert" data-testid="branding-problem">{problem}</p>}
        </div>
      ) : (
        <p className="mt-4 text-xs text-muted-foreground" data-testid="branding-read-only">Only team admins can change the report logo.</p>
      )}

      <ConfirmDialog
        open={confirmRemove}
        onOpenChange={setConfirmRemove}
        title="Remove the team logo?"
        description="New PDF reports show only the ZeroShield logo. Reports already downloaded keep theirs."
        confirmLabel="Remove logo"
        destructive
        pending={remove.isPending}
        onConfirm={() => remove.mutate()}
      />
    </section>
  );
}

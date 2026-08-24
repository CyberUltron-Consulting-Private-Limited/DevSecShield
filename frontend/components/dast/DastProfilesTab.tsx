"use client";

import { useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Play, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  createDASTProfile,
  deleteDASTProfile,
  listDASTProfiles,
  runDASTProfile,
  updateDASTProfile,
  type DastScanProfile,
  type DastScheduleKind,
} from "@/utils/backend_api";
import { formatDateIst } from "@/utils/datetime";
import { DastScheduleFields, type DastScheduleState } from "@/components/dast/DastScheduleFields";

function onceAtToIso(local: string): string | null {
  if (!local) return null;
  const trimmed = local.length === 16 ? `${local}:00` : local;
  return `${trimmed}+05:30`;
}

function onceAtFromIso(iso: string | null | undefined): string {
  if (!iso) return "";
  return iso.replace("+05:30", "").replace("Z", "").slice(0, 16);
}

const EMPTY_SCHEDULE: DastScheduleState = {
  kind: "off",
  times: ["09:00"],
  intervalHours: 4,
  weekday: 0,
  monthday: 1,
  onceAt: "",
  cron: "0 9 * * 1-5",
};

const EMPTY_FORM = {
  title: "Altoro testfire",
  target_url: "https://demo.testfire.net/index.jsp",
  login_url: "https://demo.testfire.net/login.jsp",
  xpath_of_username_field: "",
  xpath_of_password_field: "",
  username: "",
  password: "",
  xpath_of_submit_button: "",
  scan_speed: "fast" as "fast" | "medium" | "slow",
  max_urls: 1,
  schedule: EMPTY_SCHEDULE,
  enabled: true,
  consent_ok: false,
};

function scheduleFromProfile(profile: DastScanProfile): DastScheduleState {
  const cfg = profile.schedule_config || {};
  return {
    kind: (cfg.kind || profile.schedule_kind || "off") as DastScheduleKind,
    times: cfg.times?.length ? cfg.times : [profile.schedule_time || "09:00"],
    intervalHours: cfg.interval_hours || 4,
    weekday: cfg.weekday ?? profile.schedule_weekday ?? 0,
    monthday: cfg.monthday || 1,
    onceAt: onceAtFromIso(cfg.once_at),
    cron: cfg.cron || "0 9 * * 1-5",
  };
}

export function DastProfilesTab() {
  const params = useParams();
  const router = useRouter();
  const teamId = Number(params.team_id);
  const queryClient = useQueryClient();
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);

  const query = useQuery({
    queryKey: ["dast-profiles", teamId],
    queryFn: () => listDASTProfiles(teamId),
    enabled: Number.isFinite(teamId),
  });

  const profiles = query.data ?? [];

  const fillFrom = (profile: DastScanProfile) => {
    setEditingId(profile.id);
    setForm({
      title: profile.title,
      target_url: profile.target_url,
      login_url: profile.auth?.login_url || "",
      xpath_of_username_field: profile.auth?.xpath_of_username_field || "",
      xpath_of_password_field: profile.auth?.xpath_of_password_field || "",
      username: profile.auth?.username || "",
      password: "",
      xpath_of_submit_button: profile.auth?.xpath_of_submit_button || "",
      scan_speed: profile.scan_speed,
      max_urls: profile.max_urls,
      schedule: scheduleFromProfile(profile),
      enabled: profile.enabled,
      consent_ok: profile.consent_ok,
    });
  };

  const resetForm = () => {
    setEditingId(null);
    setForm(EMPTY_FORM);
  };

  const authPayload = useMemo(
    () => ({
      login_url: form.login_url,
      xpath_of_username_field: form.xpath_of_username_field,
      xpath_of_password_field: form.xpath_of_password_field,
      username: form.username,
      password: form.password,
      xpath_of_submit_button: form.xpath_of_submit_button,
    }),
    [form]
  );

  const saveMutation = useMutation({
    mutationFn: async () => {
      const schedule = form.schedule;
      const body = {
        title: form.title,
        target_url: form.target_url,
        auth: authPayload,
        scan_speed: form.scan_speed,
        max_urls: Number(form.max_urls) || 1,
        schedule_kind: schedule.kind,
        schedule_time: schedule.kind === "off" ? null : schedule.times[0] || "09:00",
        schedule_weekday: schedule.kind === "weekly" ? schedule.weekday : null,
        schedule_config: {
          kind: schedule.kind,
          times: schedule.times,
          interval_hours: schedule.kind === "every_n_hours" ? schedule.intervalHours : null,
          weekday: schedule.kind === "weekly" ? schedule.weekday : null,
          monthday: schedule.kind === "monthly" ? schedule.monthday : null,
          once_at: schedule.kind === "once" ? onceAtToIso(schedule.onceAt) : null,
          cron: schedule.kind === "cron" ? schedule.cron : null,
        },
        enabled: form.enabled,
        consent_ok: form.consent_ok,
      };
      if (editingId) {
        const { password: _pw, ...authKeep } = authPayload;
        return updateDASTProfile(teamId, editingId, {
          ...body,
          auth: form.password ? authPayload : authKeep,
        });
      }
      return createDASTProfile(teamId, body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dast-profiles", teamId] });
      resetForm();
    },
  });

  const runMutation = useMutation({
    mutationFn: (profileId: number) => runDASTProfile(teamId, profileId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["dast-profiles", teamId] });
      queryClient.invalidateQueries({ queryKey: ["dast-scans", String(teamId)] });
      if (data?.scan_id) {
        router.refresh();
      }
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (profileId: number) => deleteDASTProfile(teamId, profileId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["dast-profiles", teamId] });
      resetForm();
    },
  });

  const set = (key: keyof typeof EMPTY_FORM, value: string | number | boolean) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
      <Card>
        <CardHeader>
          <CardTitle>{editingId ? "Edit profile" : "New DAST profile"}</CardTitle>
          <CardDescription>
            Save target, login, and schedule once. Times are IST. Password is write-only and never shown after save.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="dast-profile-title">Title</Label>
              <Input id="dast-profile-title" value={form.title} onChange={(e) => set("title", e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="dast-profile-target">Target URL</Label>
              <Input id="dast-profile-target" value={form.target_url} onChange={(e) => set("target_url", e.target.value)} />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="dast-profile-login">Login URL</Label>
              <Input id="dast-profile-login" value={form.login_url} onChange={(e) => set("login_url", e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="dast-profile-user">Username</Label>
              <Input id="dast-profile-user" value={form.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="dast-profile-password">Password</Label>
              <Input
                id="dast-profile-password"
                type="password"
                value={form.password}
                placeholder={editingId ? "Leave blank to keep" : ""}
                onChange={(e) => set("password", e.target.value)}
                autoComplete="new-password"
              />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="dast-profile-user-xpath">Username field XPath</Label>
              <Input id="dast-profile-user-xpath" value={form.xpath_of_username_field} onChange={(e) => set("xpath_of_username_field", e.target.value)} />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="dast-profile-pass-xpath">Password field XPath</Label>
              <Input id="dast-profile-pass-xpath" value={form.xpath_of_password_field} onChange={(e) => set("xpath_of_password_field", e.target.value)} />
            </div>
            <div className="space-y-1.5 sm:col-span-2">
              <Label htmlFor="dast-profile-submit-xpath">Submit button XPath</Label>
              <Input id="dast-profile-submit-xpath" value={form.xpath_of_submit_button} onChange={(e) => set("xpath_of_submit_button", e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>Scan speed</Label>
              <Select value={form.scan_speed} onValueChange={(v) => set("scan_speed", v)}>
                <SelectTrigger className="cursor-pointer">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="fast">fast — 10 URLs, all checks parallel</SelectItem>
                  <SelectItem value="medium">medium — 5 URLs, all checks parallel</SelectItem>
                  <SelectItem value="slow">slow — 2 URLs, all checks parallel</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="dast-profile-max-urls">Max URLs</Label>
              <Input id="dast-profile-max-urls" type="number" min={1} value={form.max_urls} onChange={(e) => set("max_urls", Number(e.target.value))} />
            </div>
            <DastScheduleFields value={form.schedule} onChange={(schedule) => setForm((prev) => ({ ...prev, schedule }))} />
          </div>
          <label className="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
            <Checkbox checked={form.consent_ok} onCheckedChange={(v) => set("consent_ok", v === true)} />
            I confirm this target is authorized for DAST
          </label>
          <div className="flex gap-2">
            <Button
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
              onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending || !form.consent_ok}
            >
              {saveMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              {editingId ? "Save changes" : "Save profile"}
            </Button>
            {editingId && (
              <Button variant="outline" className="cursor-pointer" onClick={resetForm}>
                Cancel
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Saved profiles</CardTitle>
          <CardDescription>Run now creates a new scan. Overlapping runs are skipped. Next run is shown in IST.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {query.isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
            </div>
          ) : profiles.length === 0 ? (
            <p className="text-sm text-zinc-500 py-6 text-center">No profiles yet.</p>
          ) : (
            profiles.map((profile) => (
              <div key={profile.id} className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <p className="font-medium text-zinc-900 dark:text-white">{profile.title}</p>
                    <p className="text-xs text-zinc-500 break-all">{profile.target_url}</p>
                    <p className="text-xs text-zinc-500 mt-1">
                      {profile.schedule_kind === "off"
                        ? "Manual / Jenkins"
                        : `${profile.schedule_kind} ${(profile.schedule_config?.times || (profile.schedule_time ? [profile.schedule_time] : [])).join(", ")} IST`}
                      {profile.next_run_at ? ` · next ${formatDateIst(profile.next_run_at)}` : ""}
                      {profile.last_scan_id ? ` · last scan #${profile.last_scan_id}` : ""}
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" className="cursor-pointer" variant="outline" onClick={() => fillFrom(profile)}>
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                    onClick={() => runMutation.mutate(profile.id)}
                    disabled={runMutation.isPending || !profile.consent_ok}
                  >
                    {runMutation.isPending ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Play className="h-3 w-3 mr-1" />}
                    Run now
                  </Button>
                  <Button size="sm" variant="ghost" className="text-red-600 cursor-pointer" onClick={() => deleteMutation.mutate(profile.id)}>
                    <Trash2 className="h-3 w-3 mr-1" />
                    Delete
                  </Button>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}

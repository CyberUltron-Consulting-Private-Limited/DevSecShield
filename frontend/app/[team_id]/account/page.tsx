"use client";

// The Account page (X1, Nov 11: the user menu had only Logout; a signed-in customer could not change their password
// or end their other sessions). Reached from the user menu.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Loader2, LogOut, Mail, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
import type { InfoTipId } from "@/content/infotips";
import { changePassword, getUserProfile, logout } from "@/utils/backend_api";
import { handleApiError } from "@/utils/error-handler";
import { changePasswordProblems } from "@/utils/accountForm";
import { NEW_PASSWORD_HINT } from "@/utils/password_rules";
import { toast } from "@/utils/toast";

export default function AccountPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const profile = useQuery({ queryKey: ["user-profile"], queryFn: getUserProfile, retry: 1 });

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const [confirmSignOut, setConfirmSignOut] = useState(false);
  const problems = changePasswordProblems(current, next, confirm);
  const shown = submitted ? problems : {};

  const change = useMutation({
    mutationFn: () => changePassword(current, next),
    onSuccess: (data) => {
      setCurrent("");
      setNext("");
      setConfirm("");
      setSubmitted(false);
      setServerError(null);
      toast.success(data.message);
    },
    onError: (err) => setServerError(handleApiError(err).message),
  });

  const signOutEverywhere = useMutation({
    mutationFn: logout,
    onSettled: () => {
      queryClient.clear();
      router.push("/login");
    },
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    setServerError(null);
    if (Object.keys(problems).length === 0) change.mutate();
  };

  const field = (id: string, label: string, infoId: InfoTipId, value: string, set: (v: string) => void, autoComplete: string,
    error?: string, hint?: string) => (
    <div className="space-y-1.5">
      <FieldLabel htmlFor={id} infoId={infoId} labelClassName="text-zinc-300">{label}</FieldLabel>
      <Input id={id} type="password" value={value} autoComplete={autoComplete}
        onChange={(e) => { set(e.target.value); setServerError(null); }}
        aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
        className="bg-zinc-800 border-zinc-700 text-white" />
      {error ? (
        <p id={`${id}-error`} role="alert" className="text-xs text-red-400">{error}</p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-xs text-zinc-500">{hint}</p>
      ) : null}
    </div>
  );

  return (
    <div className="w-full max-w-2xl mx-auto px-4 py-8 space-y-8" data-testid="account-page">
      <div>
        <h1 className="text-2xl font-semibold text-white">Account</h1>
        <p className="text-sm text-zinc-400 mt-1">Your sign-in details and sessions.</p>
      </div>

      <section className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-5 space-y-3" aria-labelledby="account-details">
        <h2 id="account-details" className="text-base font-medium text-white flex items-center gap-2">
          <Mail className="h-4 w-4 text-zinc-400" aria-hidden="true" /> Sign-in
        </h2>
        {profile.isLoading ? (
          <Loader2 className="h-4 w-4 animate-spin text-zinc-400" aria-label="Loading" />
        ) : (
          <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
            <dt className="text-zinc-400">Email</dt>
            <dd className="text-white break-all" data-testid="account-email">{profile.data?.email ?? "-"}</dd>
            <dt className="text-zinc-400">Name</dt>
            <dd className="text-white">{[profile.data?.first_name, profile.data?.last_name].filter(Boolean).join(" ") || "-"}</dd>
          </dl>
        )}
        <p className="text-sm text-zinc-400 flex gap-2" data-testid="account-2fa-note">
          <ShieldCheck className="h-4 w-4 mt-0.5 shrink-0 text-green-400" aria-hidden="true" />
          Every sign-in needs your password and a 6-digit code we email to this address, so no authenticator app is
          needed.
        </p>
      </section>

      <section className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-5 space-y-4" aria-labelledby="change-password">
        <h2 id="change-password" className="text-base font-medium text-white flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-zinc-400" aria-hidden="true" /> Change password
        </h2>
        <p className="text-sm text-zinc-400">After the change, every other browser and device is signed out; this one stays signed in.</p>
        <form onSubmit={onSubmit} noValidate className="space-y-4" data-testid="change-password-form">
          {field("current-password", "Current password", "account.current_password", current, setCurrent, "current-password", shown.current)}
          {field("new-password", "New password", "account.new_password", next, setNext, "new-password", shown.next, NEW_PASSWORD_HINT)}
          {field("confirm-password", "New password again", "account.confirm_password", confirm, setConfirm, "new-password", shown.confirm)}
          {serverError && <p role="alert" className="text-sm text-red-400" data-testid="change-password-error">{serverError}</p>}
          <Button type="submit" disabled={change.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
            {change.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" aria-hidden="true" />}
            Change password
          </Button>
        </form>
      </section>

      <section className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-5 space-y-3" aria-labelledby="sessions">
        <h2 id="sessions" className="text-base font-medium text-white flex items-center gap-2">
          <LogOut className="h-4 w-4 text-zinc-400" aria-hidden="true" /> Sessions <InfoTip id="account.sessions" />
        </h2>
        <p className="text-sm text-zinc-400">Sign out of every browser and device, this one included.</p>
        <Button variant="outline" onClick={() => setConfirmSignOut(true)} className="cursor-pointer border-red-500/50 text-red-400 hover:text-red-300">
          Sign out everywhere
        </Button>
      </section>

      <Dialog open={confirmSignOut} onOpenChange={setConfirmSignOut}>
        <DialogContent className="bg-zinc-900 border-zinc-700 text-white">
          <DialogHeader>
            <DialogTitle>Sign out everywhere?</DialogTitle>
            <DialogDescription className="text-zinc-400">
              Every browser and device signed in to this account is signed out, this one too. You sign in again with
              your password and an emailed code.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setConfirmSignOut(false)} className="cursor-pointer">Cancel</Button>
            <Button onClick={() => signOutEverywhere.mutate()} disabled={signOutEverywhere.isPending}
              className="bg-red-600 hover:bg-red-700 text-white cursor-pointer" data-testid="sign-out-everywhere-confirm">
              {signOutEverywhere.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" aria-hidden="true" />}
              Sign out everywhere
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

"use client";

// Team invitation (/invite/<token>, mailed to the invited address).  A new address chooses its own password here; an
// existing account signs in as the invited address, then accepts or declines.  Nobody joins before that.
// Plain fetch, not the shared axios client: that client sends a 401 to /login and clears storage.

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { CheckCircle2, Loader2, Shield } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiBaseURL } from "@/utils/interceptors";
import { detailText, inviteLoginHref, inviteView, registerProblem, type InviteInfo } from "@/utils/invite";
import { NEW_PASSWORD_HINT } from "@/utils/password_rules";

type Load =
  | { state: "loading" }
  | { state: "gone"; message: string }
  | { state: "ready"; info: InviteInfo; signedIn: string | null }
  | { state: "done"; message: string; teamId: number | null };

function storedAccessToken(): string | null {
  try {
    return localStorage.getItem("access_token");
  } catch {
    return null;
  }
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function signedInEmail(): Promise<string | null> {
  const token = storedAccessToken();
  if (!token) return null;
  try {
    const r = await fetch(`${apiBaseURL}/get_user`, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    if (!r.ok) return null; // expired or revoked: the page offers "Sign in" instead
    const body = (await readJson(r)) as { email?: unknown } | null;
    return typeof body?.email === "string" ? body.email : null;
  } catch {
    return null;
  }
}

export default function InvitePage() {
  const params = useParams();
  const router = useRouter();
  const token = String(params?.token ?? "");
  const [load, setLoad] = useState<Load>({ state: "loading" });
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState<null | "register" | "accept" | "decline">(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await fetch(`${apiBaseURL}/invitations/${encodeURIComponent(token)}`, { cache: "no-store", referrerPolicy: "no-referrer" });
        const body = await readJson(r);
        if (cancelled) return;
        if (!r.ok) {
          setLoad({ state: "gone", message: detailText(body, "This invitation link is not valid.") });
          return;
        }
        const info = body as InviteInfo;
        const who = info.account_exists ? await signedInEmail() : null;
        if (!cancelled) setLoad({ state: "ready", info, signedIn: who });
      } catch {
        if (!cancelled) setLoad({ state: "gone", message: "Could not reach DevSecShield. Check your connection and reload." });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const post = async (action: "register" | "accept" | "decline", body?: object) => {
    setError(null);
    setBusy(action);
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      const access = storedAccessToken();
      if (action !== "register" && access && load.state === "ready" && load.signedIn) headers.Authorization = `Bearer ${access}`;
      const r = await fetch(`${apiBaseURL}/invitations/${encodeURIComponent(token)}/${action}`, {
        method: "POST", headers, body: body ? JSON.stringify(body) : undefined, cache: "no-store", referrerPolicy: "no-referrer",
      });
      const data = (await readJson(r)) as { access_token?: string; refresh_token?: string; team_id?: number } | null;
      if (!r.ok) {
        const message = detailText(data);
        if (r.status === 404 || r.status === 410) setLoad({ state: "gone", message });
        else setError(message);
        return;
      }
      if (action === "register" && data?.access_token && data?.refresh_token) {
        try {
          localStorage.setItem("access_token", data.access_token);
          localStorage.setItem("refresh_token", data.refresh_token);
        } catch {
          // storage blocked: the account exists, the invitee signs in normally
        }
      }
      setLoad({
        state: "done",
        teamId: action === "decline" ? null : data?.team_id ?? null,
        message: action === "decline" ? "You declined the invitation. Nothing was changed." : "You joined the team.",
      });
    } catch {
      setError("Could not reach DevSecShield. Check your connection and try again.");
    } finally {
      setBusy(null);
    }
  };

  const register = (e: React.FormEvent) => {
    e.preventDefault();
    const problem = registerProblem(firstName, lastName, password, confirm);
    if (problem) {
      setError(problem);
      return;
    }
    void post("register", { first_name: firstName.trim(), last_name: lastName.trim(), password });
  };

  const signOutAndSignIn = () => {
    try {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
    } catch {
      // ignore
    }
    router.push(inviteLoginHref(token));
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-background px-4 py-8">
      <Card className="mx-auto max-w-md w-full">
        <CardHeader className="space-y-2 text-center">
          <div className="mx-auto w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center text-white">
            <Shield className="h-6 w-6" />
          </div>
          <CardTitle className="text-2xl font-bold">Team invitation</CardTitle>
          {load.state === "ready" && (
            <CardDescription data-testid="invite-summary">
              <strong className="text-foreground">{load.info.invited_by}</strong> invited{" "}
              <strong className="text-foreground break-all">{load.info.email}</strong> to join the team{" "}
              <strong className="text-foreground break-words">&quot;{load.info.team_name}&quot;</strong>.
            </CardDescription>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          {load.state === "loading" && (
            <div className="flex justify-center py-6"><Loader2 className="h-6 w-6 animate-spin" aria-label="Loading" /></div>
          )}

          {load.state === "gone" && (
            <div className="space-y-4 text-center" data-testid="invite-gone">
              <p className="text-sm text-muted-foreground">{load.message}</p>
              <Link href="/login" className="text-primary hover:underline text-sm">Go to sign in</Link>
            </div>
          )}

          {load.state === "done" && (
            <div className="space-y-4 text-center" data-testid="invite-done">
              <CheckCircle2 className="h-8 w-8 mx-auto text-green-500" />
              <p className="text-sm">{load.message}</p>
              {load.teamId !== null ? (
                <Button className="w-full cursor-pointer" onClick={() => router.push(`/${load.teamId}`)}>Open the team</Button>
              ) : (
                <Link href="/home" className="text-primary hover:underline text-sm">Go to DevSecShield</Link>
              )}
            </div>
          )}

          {load.state === "ready" && (() => {
            const view = inviteView(load.info, load.signedIn);
            const expires = load.info.expires_at ? new Date(load.info.expires_at).toLocaleString() : null;
            return (
              <>
                {view === "register" && (
                  <form onSubmit={register} className="space-y-4" data-testid="invite-register">
                    <p className="text-sm text-muted-foreground">
                      Create your account for <strong className="text-foreground break-all">{load.info.email}</strong>: choose
                      your own password. You join the team when you create it.
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="space-y-2">
                        <Label htmlFor="invite-first">First name</Label>
                        <Input id="invite-first" autoComplete="given-name" value={firstName} onChange={(e) => setFirstName(e.target.value)} />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="invite-last">Last name</Label>
                        <Input id="invite-last" autoComplete="family-name" value={lastName} onChange={(e) => setLastName(e.target.value)} />
                      </div>
                    </div>
                    <input type="email" autoComplete="username" value={load.info.email} readOnly hidden />
                    <div className="space-y-2">
                      <Label htmlFor="invite-password">Password</Label>
                      <Input id="invite-password" type="password" autoComplete="new-password" aria-describedby="invite-password-rules"
                        value={password} onChange={(e) => setPassword(e.target.value)} />
                      <p id="invite-password-rules" className="text-xs text-muted-foreground">{NEW_PASSWORD_HINT}</p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="invite-confirm">Repeat the password</Label>
                      <Input id="invite-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                    </div>
                    <Button type="submit" className="w-full cursor-pointer" disabled={busy !== null}>
                      {busy === "register" && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                      Create account and join
                    </Button>
                  </form>
                )}

                {view === "sign_in" && (
                  <div className="space-y-3 text-sm" data-testid="invite-sign-in">
                    <p className="text-muted-foreground">
                      <strong className="text-foreground break-all">{load.info.email}</strong> already has an account. Sign in
                      as that address to accept or decline.
                    </p>
                    <Button className="w-full cursor-pointer" onClick={() => router.push(inviteLoginHref(token))}>
                      Sign in as {load.info.email}
                    </Button>
                  </div>
                )}

                {view === "wrong_account" && (
                  <div className="space-y-3 text-sm" data-testid="invite-wrong-account">
                    <p className="text-muted-foreground">
                      You are signed in as <strong className="text-foreground break-all">{load.signedIn}</strong>. This
                      invitation is for <strong className="text-foreground break-all">{load.info.email}</strong>.
                    </p>
                    <Button className="w-full cursor-pointer" onClick={signOutAndSignIn}>
                      Sign out and sign in as {load.info.email}
                    </Button>
                  </div>
                )}

                {view === "respond" && (
                  <div className="flex flex-col sm:flex-row gap-2" data-testid="invite-respond">
                    <Button className="flex-1 cursor-pointer" disabled={busy !== null} onClick={() => void post("accept")}>
                      {busy === "accept" && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                      Accept and join
                    </Button>
                    <Button variant="outline" className="flex-1 cursor-pointer" disabled={busy !== null} onClick={() => void post("decline")}>
                      {busy === "decline" && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                      Decline
                    </Button>
                  </div>
                )}

                {view === "register" && (
                  <button type="button" className="w-full text-sm text-muted-foreground hover:underline cursor-pointer disabled:opacity-50"
                    disabled={busy !== null} onClick={() => void post("decline")}>
                    Decline this invitation
                  </button>
                )}

                {error && <p role="alert" className="text-sm text-red-400" data-testid="invite-error">{error}</p>}
                {expires && <p className="text-xs text-muted-foreground text-center">This link works once and expires {expires}.</p>}
              </>
            );
          })()}
        </CardContent>
      </Card>
    </div>
  );
}

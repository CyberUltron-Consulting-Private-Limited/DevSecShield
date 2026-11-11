"use client";

// The mailed link of an account an administrator created: /set_password#<token>.  The token stays in the fragment
// (never sent to a server).  It is the same single-use token sign-in issues when a password must be changed, so it
// goes to POST /change_password; plain fetch, not the shared axios client (that one sends a 401 to /login).

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Loader2, Shield } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiBaseURL } from "@/utils/interceptors";
import { detailText } from "@/utils/invite";
import { NEW_PASSWORD_HINT, newPasswordProblem } from "@/utils/password_rules";

export default function SetPasswordPage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const value = decodeURIComponent(window.location.hash.replace(/^#/, ""));
    setToken(value);
    // the token is not needed in the address bar (or in history) once read
    window.history.replaceState(null, "", window.location.pathname);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const problem = newPasswordProblem(password);
    if (problem) return setError(problem);
    if (password !== again) return setError("The two passwords do not match.");
    setBusy(true);
    try {
      const r = await fetch(`${apiBaseURL}/change_password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ change_token: token, password }),
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
      let body: unknown = null;
      try {
        body = await r.json();
      } catch {
        body = null;
      }
      if (!r.ok) {
        setError(detailText(body, "This link could not be used."));
        return;
      }
      const tokens = body as { access_token?: string; refresh_token?: string };
      try {
        if (tokens.access_token && tokens.refresh_token) {
          localStorage.setItem("access_token", tokens.access_token);
          localStorage.setItem("refresh_token", tokens.refresh_token);
        }
      } catch {
        // storage blocked: the password is set, the user signs in normally
      }
      router.push("/home");
    } catch {
      setError("Could not reach DevSecShield. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-background px-4 py-8">
      <Card className="mx-auto max-w-sm w-full">
        <CardHeader className="space-y-2 text-center">
          <div className="mx-auto w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center text-white">
            <Shield className="h-6 w-6" />
          </div>
          <CardTitle className="text-2xl font-bold">Choose your password</CardTitle>
          <CardDescription>An administrator created your account. Choose the password you will sign in with.</CardDescription>
        </CardHeader>
        <CardContent>
          {token === "" ? (
            <p className="text-sm text-muted-foreground text-center" data-testid="set-password-no-token">
              This page needs the link from your email. You can also use{" "}
              <Link href="/password_reset" className="text-primary hover:underline">Forgot Password?</Link>
            </p>
          ) : (
            <form onSubmit={submit} className="space-y-4" data-testid="set-password-form">
              <div className="space-y-2">
                <Label htmlFor="set-password">Password</Label>
                <Input id="set-password" type="password" autoComplete="new-password" aria-describedby="set-password-rules"
                  value={password} onChange={(e) => setPassword(e.target.value)} />
                <p id="set-password-rules" className="text-xs text-muted-foreground">{NEW_PASSWORD_HINT}</p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="set-password-again">Repeat the password</Label>
                <Input id="set-password-again" type="password" autoComplete="new-password"
                  value={again} onChange={(e) => setAgain(e.target.value)} />
              </div>
              <Button type="submit" className="w-full cursor-pointer" disabled={busy || token === null}>
                {busy && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Save and sign in
              </Button>
              {error && (
                <p role="alert" className="text-sm text-red-400" data-testid="set-password-error">
                  {error}{" "}
                  <Link href="/password_reset" className="text-primary hover:underline">Forgot Password?</Link>
                </p>
              )}
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

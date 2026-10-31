"use client";

// Public vendor questionnaire (no login).  Uses plain fetch, not the shared axios client: that client
// redirects to /login and clears storage on a 401/403, which a vendor without an account must never hit.

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { CheckCircle2, Loader2, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { apiBaseURL } from "@/utils/interceptors";

interface Question {
  id: string;
  prompt: string;
  type: "text" | "choice";
}
interface Questionnaire {
  vendor_name: string;
  team_name: string;
  area: string;
  questions: Question[];
  expires_at: string | null;
}
type Load = { state: "loading" } | { state: "gone"; message: string } | { state: "ready"; data: Questionnaire };

const CHOICES: { value: string; label: string }[] = [
  { value: "yes", label: "Yes" },
  { value: "no", label: "No" },
  { value: "dont_know", label: "Don't know" },
];

async function detailOf(response: Response): Promise<string> {
  try {
    const body = await response.json();
    return typeof body?.detail === "string" ? body.detail : "Something went wrong. Please try again.";
  } catch {
    return "Something went wrong. Please try again.";
  }
}

export default function VendorQuestionnairePage() {
  const params = useParams();
  const token = String(params?.token ?? "");
  const [load, setLoad] = useState<Load>({ state: "loading" });
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [evidenceUrl, setEvidenceUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`${apiBaseURL}/cbom/vendor-questionnaire/${encodeURIComponent(token)}`, { cache: "no-store", referrerPolicy: "no-referrer" })
      .then(async (response) => {
        if (cancelled) return;
        if (!response.ok) {
          setLoad({ state: "gone", message: await detailOf(response) });
          return;
        }
        setLoad({ state: "ready", data: (await response.json()) as Questionnaire });
      })
      .catch(() => !cancelled && setLoad({ state: "gone", message: "Could not reach ZeroShield. Check your connection and reload." }));
    return () => {
      cancelled = true;
    };
  }, [token]);

  const submit = async () => {
    setError(null);
    const filled = Object.fromEntries(Object.entries(answers).filter(([, v]) => v.trim() !== ""));
    if (Object.keys(filled).length === 0) {
      setError("Answer at least one question.");
      return;
    }
    if (evidenceUrl && !/^https?:\/\/\S+$/i.test(evidenceUrl.trim())) {
      setError("The evidence link must start with http:// or https://");
      return;
    }
    setSubmitting(true);
    try {
      const response = await fetch(`${apiBaseURL}/cbom/vendor-questionnaire/${encodeURIComponent(token)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ answers: filled, evidence_url: evidenceUrl.trim() || null }),
        referrerPolicy: "no-referrer",
      });
      if (!response.ok) {
        setError(await detailOf(response));
        return;
      }
      setDone(true);
    } catch {
      setError("Could not reach ZeroShield. Your answers were not sent; please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900 px-4 py-10">
      <div className="max-w-2xl mx-auto space-y-6">
        <div className="flex items-center gap-2 text-zinc-900 dark:text-white">
          <span className="rounded-md bg-blue-600 p-1.5">
            <ShieldCheck className="h-4 w-4 text-white" />
          </span>
          <span className="font-semibold">ZeroShield</span>
        </div>

        {load.state === "loading" && (
          <div className="flex h-48 items-center justify-center">
            <Loader2 className="size-8 animate-spin text-blue-600" />
          </div>
        )}

        {load.state === "gone" && (
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle>This link cannot be used</CardTitle>
              <CardDescription>{load.message}</CardDescription>
            </CardHeader>
          </Card>
        )}

        {load.state === "ready" && done && (
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
                Thank you
              </CardTitle>
              <CardDescription>
                Your answers were sent to {load.data.team_name}. This link no longer works; ask your contact if you need to change
                anything.
              </CardDescription>
            </CardHeader>
          </Card>
        )}

        {load.state === "ready" && !done && (
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle>{load.data.area}</CardTitle>
              <CardDescription>
                {load.data.team_name} asks {load.data.vendor_name} to answer a few questions about cryptography. No login is needed.
                The link works once
                {load.data.expires_at ? ` and expires on ${new Date(load.data.expires_at).toLocaleDateString()}` : ""}.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {load.data.questions.map((q) => (
                <div key={q.id} className="space-y-2">
                  <Label htmlFor={`q-${q.id}`} className="leading-snug">
                    {q.prompt}
                  </Label>
                  {q.type === "choice" ? (
                    <div role="radiogroup" aria-label={q.prompt} className="flex flex-wrap gap-4">
                      {CHOICES.map((c) => (
                        <label key={c.value} className="flex items-center gap-2 text-sm cursor-pointer">
                          <input
                            type="radio"
                            name={`q-${q.id}`}
                            className="h-4 w-4 accent-blue-600"
                            checked={answers[q.id] === c.value}
                            onChange={() => setAnswers({ ...answers, [q.id]: c.value })}
                          />
                          {c.label}
                        </label>
                      ))}
                    </div>
                  ) : (
                    <Textarea
                      id={`q-${q.id}`}
                      maxLength={2000}
                      value={answers[q.id] ?? ""}
                      onChange={(e) => setAnswers({ ...answers, [q.id]: e.target.value })}
                      className="min-h-[80px]"
                    />
                  )}
                </div>
              ))}
              <div className="space-y-2">
                <Label htmlFor="q-evidence">Link to supporting evidence (optional)</Label>
                <Input
                  id="q-evidence"
                  value={evidenceUrl}
                  maxLength={1000}
                  placeholder="https://"
                  onChange={(e) => setEvidenceUrl(e.target.value)}
                />
                <p className="text-xs text-zinc-500">A policy, certificate or report. Answers with evidence count as documented.</p>
              </div>
              {error && (
                <p className="text-sm text-red-500 dark:text-red-400" role="alert">
                  {error}
                </p>
              )}
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={submitting} onClick={submit}>
                {submitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Send answers
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

"use client";

// Settings > Integrations > Jira (SOW S2): the team's Jira connection (site, account, write-only API token), the project
// and issue type of CBOM tickets, a connection test that creates nothing, and "Raise test ticket". The same connection
// serves code-scan, CI/CD and CBOM Sources tickets. Admins change it; members read.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FlaskConical, Loader2, Save, Trash2 } from "lucide-react";
import { useState } from "react";

import { ErrorBlock, Field, LoadingBlock, SectionCard, StatusBadge, type Tone } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  deleteJira,
  getJira,
  integrationKeys,
  saveJira,
  testJira,
  ticketingKeys,
  type JiraIntegration,
} from "@/utils/api/integrations";
import { showErrorToast } from "@/utils/error-handler";
import { JIRA_ADMIN_ONLY, JIRA_TOKEN_KEPT_HINT, jiraToSave } from "@/utils/jiraSettings";
import { toast } from "@/utils/toast";

import TestTicketButton, { TestTicketLink } from "./TestTicketButton";

function JiraForm({ teamId, jira }: { teamId: number; jira: JiraIntegration }) {
  const queryClient = useQueryClient();
  const [url, setUrl] = useState(jira.url ?? "");
  const [email, setEmail] = useState(jira.email ?? "");
  const [token, setToken] = useState("");
  const [project, setProject] = useState(jira.project_key ?? "");
  const [issueType, setIssueType] = useState(jira.issue_type ?? jira.issue_type_default);
  const refresh = () => queryClient.invalidateQueries({ queryKey: integrationKeys.all(teamId) });
  const isAdmin = jira.is_admin;

  const save = useMutation({
    mutationFn: () => {
      const decision = jiraToSave(email, url, token, jira.api_token_set);
      if (!decision.ok) throw new Error(decision.message);
      if (!decision.jira) throw new Error("Use Remove to disconnect Jira.");
      return saveJira(teamId, { ...decision.jira, project_key: project.trim() || null, issue_type: issueType.trim() || null,
                                expected_version: jira.row_version });
    },
    onSuccess: () => {
      toast.success("Jira saved");
      setToken("");
      refresh();
    },
    onError: (e) => (e instanceof Error && !("response" in e) ? toast.error(e.message) : showErrorToast(e)),
  });
  const test = useMutation({
    mutationFn: () => testJira(teamId),
    onSuccess: (r) => {
      if (r.ok) toast.success(`Test passed: ${r.message}`);
      else toast.error(`Test failed: ${r.message}`);
      refresh();
    },
    onError: (e) => showErrorToast(e),
  });
  const remove = useMutation({
    mutationFn: () => deleteJira(teamId),
    onSuccess: () => {
      toast.success("Jira disconnected");
      refresh();
    },
    onError: (e) => showErrorToast(e),
  });

  const last = jira.last_test;
  const tone: Tone = last?.status === "ok" ? "green" : last?.status === "failed" ? "red" : "zinc";
  const disabled = !isAdmin || save.isPending;
  const canTicket = jira.configured && Boolean(jira.project_key);
  return (
    <SectionCard
      id="int-jira"
      infoId="int.card.jira"
      title={
        <span className="flex flex-wrap items-center gap-2">
          Jira
          <StatusBadge tone={jira.configured ? "green" : "zinc"}>{jira.configured ? "Connected" : "Not set up"}</StatusBadge>
          {last && <StatusBadge tone={tone} title={last.message ?? undefined}>Test {last.status === "ok" ? "passed" : "failed"}</StatusBadge>}
        </span>
      }
      description="Opens Jira issues for findings: per finding from code scans and CI/CD, and per asset from CBOM Sources runs. The same connection serves all of them."
    >
      <div className="space-y-4" data-testid="int-jira">
        {!isAdmin && <p className="text-sm text-zinc-500">{JIRA_ADMIN_ONLY}</p>}
        {last?.message && <p className="text-xs text-zinc-500">Last test {last.at ? new Date(last.at).toLocaleString() : ""}: {last.message}</p>}
        <TestTicketLink ticket={jira.last_test_ticket} />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field infoId="int.jira.url" label="Jira URL" htmlFor="int-jira-url" required>
            <Input id="int-jira-url" type="url" value={url} placeholder="https://bank.atlassian.net" disabled={disabled}
                   onChange={(e) => setUrl(e.target.value)} />
          </Field>
          <Field infoId="int.jira.email" label="Account email" htmlFor="int-jira-email" required>
            <Input id="int-jira-email" type="email" value={email} placeholder="secops-bot@bank.in" disabled={disabled}
                   onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field infoId="int.jira.token" label="API token" htmlFor="int-jira-token" required={!jira.api_token_set}
                 hint={jira.api_token_set ? JIRA_TOKEN_KEPT_HINT : "Encrypted at rest; never shown again."}>
            <Input id="int-jira-token" type="password" autoComplete="new-password" value={token} disabled={disabled}
                   placeholder={jira.api_token_set ? "Saved. Leave blank to keep it" : ""}
                   onChange={(e) => setToken(e.target.value)} />
          </Field>
          <Field infoId="int.jira.project" label="Project for CBOM tickets" htmlFor="int-jira-project"
                 hint="The project key (such as SEC) or the numeric project id.">
            <Input id="int-jira-project" value={project} placeholder="SEC" maxLength={32} disabled={disabled}
                   onChange={(e) => setProject(e.target.value)} />
          </Field>
          <Field infoId="int.jira.issue_type" label="Issue type" htmlFor="int-jira-issue-type">
            <Input id="int-jira-issue-type" value={issueType} placeholder={jira.issue_type_default} maxLength={64} disabled={disabled}
                   onChange={(e) => setIssueType(e.target.value)} />
          </Field>
        </div>
        {isAdmin && (
          <div className="flex flex-wrap items-center gap-2">
            <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending}
                    onClick={() => save.mutate()} data-testid="int-jira-save">
              {save.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Save className="h-4 w-4 mr-1.5" />}
              Save
            </Button>
            <Button variant="outline" className="cursor-pointer" disabled={!jira.configured || test.isPending}
                    onClick={() => test.mutate()} data-testid="int-jira-test" title="Signs in and checks the project; creates nothing">
              {test.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <FlaskConical className="h-4 w-4 mr-1.5" />}
              Send test
            </Button>
            <TestTicketButton teamId={teamId} kind="jira" disabled={!canTicket}
                              title={canTicket ? "Creates one labelled test issue in the project" : "Save the connection and the project first"} />
            {jira.configured && (
              <Button variant="outline" className="cursor-pointer text-red-500" disabled={remove.isPending}
                      onClick={() => { if (window.confirm("Disconnect Jira? Code-scan, CI/CD and CBOM tickets stop until it is set up again.")) remove.mutate(); }}>
                <Trash2 className="h-4 w-4 mr-1.5" />Remove
              </Button>
            )}
          </div>
        )}
      </div>
    </SectionCard>
  );
}

export default function JiraCard({ teamId }: { teamId: number }) {
  const q = useQuery({ queryKey: ticketingKeys.jira(teamId), queryFn: () => getJira(teamId) });
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  // keyed by the saved state: a save reloads the form; a background refetch does not
  return <JiraForm key={`${q.data.row_version}-${q.data.url}-${q.data.email}-${q.data.api_token_set}`} teamId={teamId} jira={q.data} />;
}

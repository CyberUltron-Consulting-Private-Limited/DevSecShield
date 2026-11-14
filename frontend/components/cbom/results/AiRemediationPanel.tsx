"use client";

/**
 * AI remediation assistant for one CBOM finding (CB-38 PR-6). An addition UNDER the knowledge-base remediation, which
 * always renders first and needs no model. Renders nothing at all unless GET /{team}/cbom/ai/status says the
 * assistant is available. Every answer has passed the backend's validator (KB-only CVE / CWE ids, cited steps,
 * KB-only commands and links); it is shown as plain text (React-escaped), never as HTML or markdown.
 */
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Loader2, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  askCbomAi,
  getCbomAiStatus,
  type CbomAiAnswer,
  type CbomAiMode,
  type CbomAiSubject,
} from "@/utils/backend_api";
import {
  MAX_QUESTION, aiPanelVisible, answerBadge, canAsk, citationLabel, egressLines, egressNote, outcomeNote,
} from "./aiPanelLogic";
import { InfoTip } from "@/components/ui/info-tip";

export interface AiRemediationPanelProps {
  teamId: number;
  subject: CbomAiSubject;
}

function CitationChips({ cites, items }: { cites: string[]; items: CbomAiAnswer["items"] }) {
  return (
    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
      {cites.map((c) => (
        <Badge key={c} variant="outline" className="px-1 py-0 text-[10px] font-normal" title={citationLabel(c, items)}
          data-testid="cbom-ai-cite">
          {citationLabel(c, items)}
        </Badge>
      ))}
    </span>
  );
}

export default function AiRemediationPanel({ teamId, subject }: AiRemediationPanelProps) {
  const [mode, setMode] = useState<CbomAiMode | null>(null);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<CbomAiAnswer | null>(null);
  const validTeam = Number.isInteger(teamId) && teamId > 0;
  const status = useQuery({
    queryKey: ["cbom-ai-status", teamId],
    queryFn: () => getCbomAiStatus(teamId),
    enabled: validTeam,
    staleTime: 60_000,
    retry: false,
  });
  const ask = useMutation({
    mutationFn: (m: CbomAiMode) => askCbomAi({ team_id: teamId, subject, mode: m, question: m === "question" ? question.trim() : undefined }),
    onMutate: (m) => { setMode(m); setAnswer(null); },
    onSuccess: (a) => setAnswer(a),
  });

  if (!aiPanelVisible(status.data)) return null;
  const note = outcomeNote(answer);
  const run = (m: CbomAiMode) => { if (canAsk(m, question) && !ask.isPending) ask.mutate(m); };

  return (
    <div className="space-y-3 rounded-md border border-zinc-200 p-3 dark:border-zinc-700" data-testid="cbom-ai-panel">
      <div className="flex flex-wrap items-center gap-2">
        <Sparkles className="h-4 w-4 text-violet-600 dark:text-violet-400" />
        <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">AI assistant</span>
        <InfoTip id="cbom.ai.panel" />
        <span className="text-[11px] text-zinc-500" data-testid="cbom-ai-egress">{egressNote(status.data)}</span>
      </div>
      {egressLines(status.data).length > 1 && (
        <ul className="list-disc pl-5 text-[11px] text-zinc-500" data-testid="cbom-ai-egress-list">
          {egressLines(status.data).map((line) => <li key={line} className="break-all">{line}</li>)}
        </ul>
      )}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" className="h-7 text-xs" disabled={ask.isPending} onClick={() => run("explain")}
          data-testid="cbom-ai-explain">Explain</Button>
        <Button size="sm" variant="outline" className="h-7 text-xs" disabled={ask.isPending} onClick={() => run("plan")}
          data-testid="cbom-ai-plan">Plan</Button>
        <Button size="sm" variant="outline" className="h-7 text-xs" disabled={ask.isPending}
          onClick={() => setMode("question")}
          data-testid="cbom-ai-question-toggle">Ask a question</Button>
      </div>
      {mode === "question" && (
        <div className="space-y-2">
          <Textarea value={question} maxLength={MAX_QUESTION} rows={2} className="text-sm"
            placeholder="For example: which of these steps applies to an nginx reverse proxy?"
            onChange={(e) => setQuestion(e.target.value)} data-testid="cbom-ai-question" />
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1 text-[10px] text-zinc-500">{question.length}/{MAX_QUESTION} <InfoTip id="cbom.ai.question" /></span>
            <Button size="sm" className="h-7 text-xs" disabled={ask.isPending || !canAsk("question", question)}
              onClick={() => run("question")} data-testid="cbom-ai-ask">Ask</Button>
          </div>
        </div>
      )}
      {ask.isPending && (
        <div className="flex items-center gap-2 text-xs text-zinc-500"><Loader2 className="h-4 w-4 animate-spin" /> Asking the model (up to 90 s)…</div>
      )}
      {ask.isError && (
        <div className="flex items-center gap-2 text-xs text-amber-700 dark:text-amber-400" data-testid="cbom-ai-request-error">
          <AlertTriangle className="h-4 w-4" /> The AI assistant could not be reached. The knowledge-base remediation above is unaffected.
        </div>
      )}
      {answer && (
        <div className="space-y-2" data-testid="cbom-ai-answer" data-status={answer.status}>
          {note && (
            <div className="flex gap-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-300"
              data-testid={answer.status === "withheld" ? "cbom-ai-withheld" : "cbom-ai-note"}>
              <AlertTriangle className="h-4 w-4 shrink-0" />{note.text}
            </div>
          )}
          {answer.summary && <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{answer.summary}</p>}
          {answer.steps.length > 0 && (
            <ol className="list-decimal space-y-1 pl-5 text-sm text-zinc-700 dark:text-zinc-300">
              {answer.steps.map((s, i) => (
                <li key={i} className="whitespace-pre-wrap break-words">{s.text}<CitationChips cites={s.cites} items={answer.items} /></li>
              ))}
            </ol>
          )}
          {answer.commands.length > 0 && (
            <div className="space-y-1">
              {answer.commands.map((c, i) => (
                <div key={i} className="space-y-0.5">
                  <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-zinc-900 px-3 py-2 font-mono text-xs text-zinc-100"><code>{c.command}</code></pre>
                  {c.cite && <CitationChips cites={[c.cite]} items={answer.items} />}
                </div>
              ))}
            </div>
          )}
          {answer.caveats.length > 0 && answer.status === "ok" && (
            <ul className="list-disc space-y-0.5 pl-5 text-xs text-zinc-500">{answer.caveats.map((c, i) => <li key={i}>{c}</li>)}</ul>
          )}
          {(answer.status === "ok" || answer.status === "withheld") && (
            <Badge variant="outline" className="h-auto max-w-full whitespace-normal break-words text-left text-[10px] font-normal"
              data-testid="cbom-ai-badge">{answerBadge(answer)}</Badge>
          )}
        </div>
      )}
    </div>
  );
}

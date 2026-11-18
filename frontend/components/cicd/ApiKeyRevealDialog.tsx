"use client";

// Shows a CI/CD API key once, right after create or rotate (issue #99). The key lives only in this component's props
// (the mutation answer): it is never written to storage, the URL or the query cache, and is gone once the dialog
// closes. The dialog closes only through its button, so a stray click or Escape cannot lose the key.

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Check, Copy, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "@/utils/toast";
import { apiBaseURL } from "@/utils/interceptors";
import { CI_SECRET_NAME, KEY_ONCE_NOTE, ciSnippets } from "@/components/cicd/apiKey";

interface ApiKeyRevealDialogProps {
  apiKey: string | null; // open while set
  scanType: string;
  title: string; // "Integration created" / "New API key issued"
  onDone: () => void;
}

async function copyText(text: string, what: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(`${what} copied to clipboard`);
    return true;
  } catch {
    toast.error(`Could not copy the ${what.toLowerCase()}; select it and copy it by hand`);
    return false;
  }
}

export default function ApiKeyRevealDialog({ apiKey, scanType, title, onDone }: ApiKeyRevealDialogProps) {
  const kind = (scanType || "sast").toLowerCase();
  const snippets = useMemo(() => ciSnippets(kind, `${apiBaseURL}/cicd/${kind}/scan`), [kind]);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);

  // A reload or back navigation would drop the key: ask the browser to confirm while it is on screen
  useEffect(() => {
    if (!apiKey) return;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [apiKey]);

  const close = () => {
    setCopiedKey(false);
    setCopiedSnippet(null);
    onDone();
  };

  return (
    <Dialog open={!!apiKey} onOpenChange={(open) => { if (!open) close(); }}>
      <DialogContent
        showCloseButton={false}
        onInteractOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
        className="sm:max-w-3xl max-h-[90vh] overflow-y-auto"
        data-testid="cicd-key-reveal"
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><KeyRound className="h-5 w-5" />{title}</DialogTitle>
          <DialogDescription>
            Your CI/CD API key. Pipelines send it in the <code className="text-xs">cicd-api-key</code> header.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <div className="flex flex-col sm:flex-row gap-2 sm:items-start">
            <code
              data-testid="cicd-key-value"
              className="flex-1 min-w-0 break-all select-all rounded border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900 px-3 py-2 text-xs font-mono text-zinc-900 dark:text-zinc-100"
            >
              {apiKey}
            </code>
            <Button
              type="button"
              className="cursor-pointer shrink-0"
              onClick={async () => { if (apiKey && (await copyText(apiKey, "API key"))) setCopiedKey(true); }}
            >
              {copiedKey ? <Check className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
              {copiedKey ? "Copied" : "Copy key"}
            </Button>
          </div>
          <p className="flex items-start gap-2 rounded border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40 px-3 py-2 text-sm text-amber-900 dark:text-amber-200">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
            <span>{KEY_ONCE_NOTE}</span>
          </p>
        </div>

        {snippets.length > 0 ? (
          <div className="space-y-2 min-w-0">
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">Add it to your pipeline</h3>
            <p className="text-xs text-zinc-600 dark:text-zinc-400">
              Store the key as the secret <code className="text-xs">{CI_SECRET_NAME}</code>, then paste the file. The
              files never contain the key. The Integration Guide tab has the same files with step-by-step setup.
            </p>
            <Tabs defaultValue={snippets[0].id} className="min-w-0">
              <TabsList className="flex flex-wrap h-auto">
                {snippets.map((s) => (
                  <TabsTrigger key={s.id} value={s.id} className="cursor-pointer">{s.label}</TabsTrigger>
                ))}
              </TabsList>
              {snippets.map((s) => (
                <TabsContent key={s.id} value={s.id} className="space-y-2 min-w-0">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                    <div className="text-xs text-zinc-600 dark:text-zinc-400 min-w-0">
                      <div><strong>File:</strong> <code>{s.file}</code></div>
                      <div><strong>Secret:</strong> {s.secretHelp}</div>
                    </div>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="cursor-pointer shrink-0"
                      data-testid={`cicd-snippet-copy-${s.id}`}
                      onClick={async () => { if (await copyText(s.text, `${s.label} file`)) setCopiedSnippet(s.id); }}
                    >
                      {copiedSnippet === s.id ? <Check className="h-4 w-4 mr-2" /> : <Copy className="h-4 w-4 mr-2" />}
                      {copiedSnippet === s.id ? "Copied" : "Copy file"}
                    </Button>
                  </div>
                  <pre
                    data-testid={`cicd-snippet-${s.id}`}
                    className="max-h-64 overflow-auto rounded border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-3 text-xs font-mono text-zinc-900 dark:text-zinc-100 whitespace-pre"
                  >
                    {s.text}
                  </pre>
                </TabsContent>
              ))}
            </Tabs>
          </div>
        ) : (
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            Store the key as the Jenkins credential <code className="text-xs">{CI_SECRET_NAME}</code>. The Integration
            Guide tab has the Jenkinsfile for DAST.
          </p>
        )}

        <DialogFooter>
          <Button type="button" className="cursor-pointer" onClick={close} data-testid="cicd-key-done">
            I have saved the key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

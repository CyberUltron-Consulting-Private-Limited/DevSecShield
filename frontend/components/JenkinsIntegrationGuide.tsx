"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import { toast } from "@/utils/toast";
import { ScrollArea } from "@/components/ui/scroll-area";
import { apiBaseURL } from "@/utils/interceptors";
import { CBOM_GATE_NOTE, isCbom, jenkinsfile } from "@/components/cicd/ciTemplates";

interface JenkinsIntegrationGuideProps {
  teamId: number;
  scanType?: string;
}

export function JenkinsGuide({ scanType = "sast" }: JenkinsIntegrationGuideProps) {
  const [copied, setCopied] = useState(false);
  const kind = (scanType || "sast").toLowerCase();
  const label = kind.toUpperCase();
  const endpoint = `${apiBaseURL}/cicd/${kind}/scan`;

  // The Jenkinsfile (components/cicd/ciTemplates.ts) reads the key from the Jenkins credential CICD_API_KEY; it never
  // contains the key. A CBOM Jenkinsfile ends with the policy gate stage.
  const jenkinsfileContent = useMemo(() => jenkinsfile({ kind, endpoint }), [endpoint, kind]);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(jenkinsfileContent);
      setCopied(true);
      toast.success("Jenkinsfile content copied to clipboard!");
      setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch (error) {
      toast.error("Failed to copy Jenkinsfile content");
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">
          Jenkins Integration
        </h3>
        <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
          Follow these steps to integrate DevSecShield {label} scanning into your Jenkins pipeline.
        </p>
      </div>

      {/* Instructions */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Integration Steps</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="list-decimal list-inside space-y-3 text-sm text-zinc-700 dark:text-zinc-300">
            <li>
              Copy the Jenkinsfile content below by clicking the copy button.
            </li>
            <li>
              In your repository root directory, create a file named <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">Jenkinsfile</code> (case-sensitive, no extension).
            </li>
            <li>
              Paste the copied Jenkinsfile content into this file.
            </li>
            <li>
              Add the CI/CD API key as a Jenkins credential (the Jenkinsfile reads it with <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">credentials(&apos;CICD_API_KEY&apos;)</code>):
              <ol className="list-decimal list-inside ml-4 mt-2 space-y-2 text-xs">
                <li>
                  In your Jenkins dashboard, go to <strong>Manage Jenkins</strong> → <strong>Credentials</strong>
                </li>
                <li>
                  Click on your domain (usually "Global") or create a new domain
                </li>
                <li>
                  Click <strong>Add Credentials</strong>
                </li>
                <li>
                  Select <strong>Secret text</strong> as the kind
                </li>
                <li>
                  Enter <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">CICD_API_KEY</code> as the ID
                </li>
                <li>
                  Paste in the <strong>Secret</strong> field the API key DevSecShield showed once when this integration was created or its key was last rotated (rotate it on this page if you no longer have it)
                </li>
                <li>
                  Click <strong>OK</strong> to save
                </li>
              </ol>
            </li>
            <li>
              Commit and push the Jenkinsfile to your repository.
            </li>
            <li>
              In Jenkins, create a new Pipeline job or update an existing one:
              <ol className="list-decimal list-inside ml-4 mt-2 space-y-2 text-xs">
                <li>
                  Go to <strong>New Item</strong> (or edit existing job)
                </li>
                <li>
                  Select <strong>Pipeline</strong> as the job type
                </li>
                <li>
                  In the Pipeline configuration, select <strong>Pipeline script from SCM</strong>
                </li>
                <li>
                  Choose your SCM (Git, SVN, etc.) and configure the repository URL
                </li>
                <li>
                  Set the script path to <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">Jenkinsfile</code>
                </li>
                <li>
                  Save the configuration
                </li>
              </ol>
            </li>
            <li>
              Run the pipeline. The {label} scan will execute automatically as part of the pipeline.
              {isCbom(kind) && <> {CBOM_GATE_NOTE}</>}
            </li>
          </ol>
        </CardContent>
      </Card>

      {/* Jenkinsfile Display */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base">Jenkinsfile</CardTitle>
            <CardDescription>
              Copy this Jenkinsfile to your repository root directory
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={copyToClipboard}
            className="cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="h-4 w-4 mr-2 text-green-600" />
                Copied!
              </>
            ) : (
              <>
                <Copy className="h-4 w-4 mr-2" />
                Copy Jenkinsfile
              </>
            )}
          </Button>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[500px] w-full rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-4">
            <pre className="text-xs font-mono text-zinc-900 dark:text-zinc-100 whitespace-pre-wrap">
              {jenkinsfileContent}
            </pre>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}


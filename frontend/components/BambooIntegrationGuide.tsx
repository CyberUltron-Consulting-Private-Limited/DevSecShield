"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import { toast } from "@/utils/toast";
import { ScrollArea } from "@/components/ui/scroll-area";
import { apiBaseURL } from "@/utils/interceptors";
import { CBOM_GATE_NOTE, bambooScript, isCbom } from "@/components/cicd/ciTemplates";

interface BambooIntegrationGuideProps {
  apiKey: string;
  scanType?: string;
}

export function BambooGuide({ apiKey, scanType = "sast" }: BambooIntegrationGuideProps) {
  const [copied, setCopied] = useState(false);
  const kind = (scanType || "sast").toLowerCase();
  const label = kind.toUpperCase();
  const endpoint = `${apiBaseURL}/cicd/${kind}/scan`;

  // Generate script content based on selections (components/cicd/ciTemplates.ts; a CBOM script ends with the policy
  // gate). The key is read from the Bamboo variable, never written into the script, so the copied and the displayed
  // scripts are the same.
  const scriptContent = useMemo(() => bambooScript({ kind, endpoint }), [endpoint, kind]);

  // Displayed script (it holds no key)
  const displayedScriptContent = scriptContent;

  const copyToClipboard = async () => {
    try {
      // Copy the full content with unmasked API key
      await navigator.clipboard.writeText(scriptContent);
      setCopied(true);
      toast.success("Script content copied to clipboard!");
      setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch (error) {
      toast.error("Failed to copy script content");
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">
          Atlassian Bamboo Integration
        </h3>
        <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
          Follow these steps to integrate DevSecShield {label} scanning into your Atlassian Bamboo plan.
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
              <strong>Run the Atlassian Bamboo Service and Agent</strong>
              <br />
              <span className="text-zinc-600 dark:text-zinc-400">Ensure the Atlassian Bamboo service and agent are running.</span>
            </li>
            <li>
              <strong>Create a Project</strong>
              <br />
              <span className="text-zinc-600 dark:text-zinc-400">Create a new project in Atlassian Bamboo.</span>
            </li>
            <li>
              <strong>Create a Plan</strong>
              <br />
              <span className="text-zinc-600 dark:text-zinc-400">Set up a plan for the project to manage your builds and scans.</span>
            </li>
            <li>
              <strong>Configure Your Code Repository</strong>
              <br />
              <span className="text-zinc-600 dark:text-zinc-400">Go to the plan configuration and link your code repository.</span>
            </li>
            <li>
              <strong>Create a New Stage</strong>
              <br />
              <span className="text-zinc-600 dark:text-zinc-400">Go to the Stages section and create a new stage named <strong>Security Scans</strong>. Move this stage to the top and delete or disable the default stage.</span>
            </li>
            <li>
              <strong>Add a Job</strong>
              <br />
              <span className="text-zinc-600 dark:text-zinc-400">Add a job under the Security Scans stage named <strong>{label} Scan</strong>.</span>
            </li>
            <li>
              <strong>Configure the {label} Scan Job</strong>
              <ol className="list-decimal list-inside ml-4 mt-2 space-y-2 text-xs">
                <li>Go to the {label} Scan job</li>
                <li>Add a new task and select the task type as <strong>Script</strong></li>
                <li>Follow the script configuration steps below</li>
              </ol>
            </li>
            <li>
              <strong>Script Configuration</strong>
              <ol className="list-decimal list-inside ml-4 mt-2 space-y-2 text-xs">
                <li>
                  <strong>Task Description:</strong> Enter a recognizable description like "{label} Scan"
                </li>
                <li>
                  <strong>Interpreter:</strong> Choose <code className="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded text-xs font-mono">Shell</code> for Linux
                </li>
                <li>
                  <strong>Script Location:</strong> Select <code className="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded text-xs font-mono">Inline</code>
                </li>
                <li>
                  <strong>Script Body:</strong> Copy the script below by clicking the copy button and paste it into the Script Body field
                </li>
              </ol>
            </li>
            <li>
              <strong>Configure Bamboo Variables</strong>
              <ol className="list-decimal list-inside ml-4 mt-2 space-y-2 text-xs">
                <li>Go to your plan configuration and navigate to <strong>Variables</strong></li>
                <li>Click <strong>Add Variable</strong></li>
                <li>Create a new variable:
                  <div className="mt-2 p-2 bg-zinc-50 dark:bg-zinc-800 rounded border border-zinc-200 dark:border-zinc-700">
                    <p className="text-xs font-mono text-zinc-900 dark:text-zinc-100">
                      Variable: <span className="text-blue-600 dark:text-blue-400">cicd_api_key</span>
                    </p>
                    <p className="text-xs font-mono text-zinc-900 dark:text-zinc-100 mt-1">
                      Value: <span className="text-zinc-500">{apiKey.substring(0, 20)}...</span>
                    </p>
                    <p className="text-xs font-mono text-zinc-900 dark:text-zinc-100 mt-1">
                      Type: <span className="text-blue-600 dark:text-blue-400">Password</span> (to hide the value)
                    </p>
                  </div>
                </li>
                <li>
                  <strong>Important:</strong> Make sure to set the <code className="bg-zinc-100 dark:bg-zinc-800 px-1 py-0.5 rounded text-xs font-mono">cicd_api_key</code> variable as masked/secure so it won't be exposed in logs
                </li>
              </ol>
            </li>
            <li>
              <strong>Run the Plan</strong>
              <br />
              <span className="text-zinc-600 dark:text-zinc-400">After completing the configuration, manually run the plan and check the logs in Atlassian Bamboo for details of the found vulnerabilities. Detailed information on the scan will be available in the DevSecShield dashboard.{isCbom(kind) && <> {CBOM_GATE_NOTE}</>}</span>
            </li>
          </ol>
        </CardContent>
      </Card>

      {/* Script Display */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base">{label} Scan Script</CardTitle>
            <CardDescription>
              Copy this script to use in your Bamboo Script task
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
                Copy Script
              </>
            )}
          </Button>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px] w-full rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-4">
            <pre className="text-xs font-mono text-zinc-900 dark:text-zinc-100 whitespace-pre-wrap">
              {displayedScriptContent}
            </pre>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

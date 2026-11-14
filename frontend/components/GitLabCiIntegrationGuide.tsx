"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Copy, Check } from "lucide-react";
import { toast } from "@/utils/toast";
import { ScrollArea } from "@/components/ui/scroll-area";
import { apiBaseURL } from "@/utils/interceptors";
import { CBOM_GATE_NOTE, gitlabCi, isCbom } from "@/components/cicd/ciTemplates";

interface GitLabCiIntegrationGuideProps {
  scanType?: string;
}

const code = "bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono";

export function GitLabCiGuide({ scanType = "sast" }: GitLabCiIntegrationGuideProps) {
  const kind = (scanType || "sast").toLowerCase();
  const label = kind.toUpperCase();
  const endpoint = `${apiBaseURL}/cicd/${kind}/scan`;
  const [branch, setBranch] = useState<string>("main");
  const [copied, setCopied] = useState(false);

  // The job reads the key from the CI/CD variable, so the copied and the displayed files are the same.
  const yamlContent = useMemo(() => gitlabCi({ kind, endpoint, branch }), [branch, endpoint, kind]);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(yamlContent);
      setCopied(true);
      toast.success("GitLab CI job copied to clipboard!");
      setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch {
      toast.error("Failed to copy the GitLab CI job");
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">GitLab CI Integration</h3>
        <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
          Follow these steps to integrate DevSecShield {label} scanning into your GitLab CI/CD pipeline.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Configuration</CardTitle>
          <CardDescription>Set the branch name to generate the job.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="gitlab-branch">Branch Name *</Label>
              <Input id="gitlab-branch" value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Integration Steps</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="list-decimal list-inside space-y-3 text-sm text-zinc-700 dark:text-zinc-300">
            <li>Copy the job below by clicking the copy button.</li>
            <li>
              Paste it into <code className={code}>.gitlab-ci.yml</code> at the root of your GitLab project (create the
              file if it does not exist). It runs on a Docker runner with the <code className={code}>alpine</code> image.
            </li>
            <li>
              Add the CI/CD API key as a variable in your GitLab project:
              <ol className="list-decimal list-inside ml-4 mt-2 space-y-2 text-xs">
                <li>
                  Go to <strong>Settings</strong> → <strong>CI/CD</strong> → <strong>Variables</strong> and click{" "}
                  <strong>Add variable</strong>
                </li>
                <li>
                  Key: <code className={code}>CICD_API_KEY</code>
                </li>
                <li>
                  Value: your API key
                  <div className="mt-2 p-2 bg-zinc-50 dark:bg-zinc-800 rounded border border-zinc-200 dark:border-zinc-700">
                    <p className="text-xs font-mono text-zinc-900 dark:text-zinc-100 break-all">
                      Value: <span className="text-zinc-500">the API key DevSecShield showed once when this integration was created or its key was last rotated (rotate it on this page if you no longer have it)</span>
                    </p>
                  </div>
                </li>
                <li>
                  Select <strong>Mask variable</strong> so the key never appears in job logs
                </li>
              </ol>
            </li>
            <li>Commit and push the file.</li>
            <li>
              The {label} scan runs on every merge request and on every push to the selected branch.
              {isCbom(kind) && <> {CBOM_GATE_NOTE}</>}
            </li>
          </ol>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base">GitLab CI Job</CardTitle>
            <CardDescription>
              Add this job to your <code className="text-xs">.gitlab-ci.yml</code>
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={copyToClipboard} className="cursor-pointer">
            {copied ? (
              <>
                <Check className="h-4 w-4 mr-2 text-green-600" />
                Copied!
              </>
            ) : (
              <>
                <Copy className="h-4 w-4 mr-2" />
                Copy YAML
              </>
            )}
          </Button>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px] w-full rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-4">
            <pre className="text-xs font-mono text-zinc-900 dark:text-zinc-100 whitespace-pre-wrap">{yamlContent}</pre>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Copy, Check } from "lucide-react";
import { toast } from "sonner";
import { ScrollArea } from "@/components/ui/scroll-area";

interface GitHubActionsIntegrationGuideProps {
  apiKey: string;
}

export function GitHubActionsGuide({ apiKey }: GitHubActionsIntegrationGuideProps) {
  const [appLang, setAppLang] = useState<"python" | "javascript" | "java" | "php" | "c" | "ruby" | "rust" | "swift" | "csharp" | "kotlin">("python");
  const [branch, setBranch] = useState<string>("main");
  const [copied, setCopied] = useState(false);

  // Generate YAML content based on selections
  const yamlContent = useMemo(() => {
    // Use string concatenation to avoid parsing ${{ }} as template literal syntax
    const githubActionsSecret = '${{ secrets.CICD_API_KEY }}';
    return `name: SAST Check
on:
  push:
    branches: [ ${branch} ]  # Adjust this to your master branch name
  pull_request:
    branches: [ ${branch} ]  # Optionally run on PRs
jobs:
  sast-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Create project zip
        run: |
          zip -r project.zip . -x "*.git*" "*/node_modules/*" "*/vendor/*" "*.zip"
      
      - name: Perform SAST Scan
        id: sast
        run: |
          RESPONSE=$(curl -X POST \\
            -H "cicd-api-key: ${githubActionsSecret}" \\
            -F "zip_file=@project.zip" \\
            -F "app_lang=${appLang}" \\
            https://devsecshieldapi.zeroshield.ai/cicd/sast/scan)          
          
          
          # Check for error in response
          ERROR=$(echo "$RESPONSE" | jq -r '.error // empty')
          if [ ! -z "$ERROR" ]; then
            echo "Error: $ERROR"
            exit 1
          else
            VULNS=$(echo "$RESPONSE" | jq -r '.vulnerabilities')
            echo "Vulnerabilities:"
            echo "$VULNS"
          fi`;
  }, [appLang, branch]);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(yamlContent);
      setCopied(true);
      toast.success("YAML content copied to clipboard!");
      setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch (error) {
      toast.error("Failed to copy YAML content");
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">
          GitHub Actions Integration
        </h3>
        <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
          Follow these steps to integrate DevSecShield SAST scanning into your GitHub Actions workflow.
        </p>
      </div>

      {/* Configuration Options */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Configuration</CardTitle>
          <CardDescription>
            Select your application language and branch to generate the workflow file.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="app_lang">Application Language *</Label>
              <Select
                value={appLang}
                onValueChange={(value) => setAppLang(value as typeof appLang)}
              >
                <SelectTrigger id="app_lang">
                  <SelectValue placeholder="Select language" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="python">Python</SelectItem>
                  <SelectItem value="javascript">JavaScript</SelectItem>
                  <SelectItem value="java">Java</SelectItem>
                  <SelectItem value="php">PHP</SelectItem>
                  <SelectItem value="c">C</SelectItem>
                  <SelectItem value="ruby">Ruby</SelectItem>
                  <SelectItem value="rust">Rust</SelectItem>
                  <SelectItem value="swift">Swift</SelectItem>
                  <SelectItem value="csharp">C#</SelectItem>
                  <SelectItem value="kotlin">Kotlin</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="branch">Branch Name *</Label>
              <Input
                id="branch"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                placeholder="main"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Instructions */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Integration Steps</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="list-decimal list-inside space-y-3 text-sm text-zinc-700 dark:text-zinc-300">
            <li>
              Copy the workflow YAML file below by clicking the copy button.
            </li>
            <li>
              In your GitHub repository, navigate to <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">.github/workflows/</code> directory.
            </li>
            <li>
              Create a new file (e.g., <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">sast-check.yml</code>) and paste the copied YAML content.
            </li>
            <li>
              Add the CI/CD API key as a secret in your GitHub repository:
              <ol className="list-decimal list-inside ml-4 mt-2 space-y-2 text-xs">
                <li>
                  Navigate to your GitHub repository on GitHub.com
                </li>
                <li>
                  Click on <strong>Settings</strong> (in the repository navigation bar)
                </li>
                <li>
                  In the left sidebar, click on <strong>Secrets and variables</strong> → <strong>Actions</strong>
                </li>
                <li>
                  Click the <strong>New repository secret</strong> button
                </li>
                <li>
                  Enter the secret name: <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">CICD_API_KEY</code>
                </li>
                <li>
                  Paste your API key in the <strong>Secret</strong> field. 
                  <div className="mt-2 p-2 bg-zinc-50 dark:bg-zinc-800 rounded border border-zinc-200 dark:border-zinc-700">
                    <p className="text-xs text-zinc-600 dark:text-zinc-400 mb-1">Example:</p>
                    <p className="text-xs font-mono text-zinc-900 dark:text-zinc-100 break-all">
                      Name: <span className="text-blue-600 dark:text-blue-400">CICD_API_KEY</span>
                    </p>
                    <p className="text-xs font-mono text-zinc-900 dark:text-zinc-100 break-all mt-1">
                      Secret: <span className="text-zinc-500">{apiKey.substring(0, 20)}...</span>
                    </p>
                  </div>
                </li>
                <li>
                  Click <strong>Add secret</strong> to save it
                </li>
              </ol>
            </li>
            <li>
              Commit and push the workflow file to your repository.
            </li>
            <li>
              The SAST scan will run automatically on every push and pull request to the selected branch.
            </li>
          </ol>
        </CardContent>
      </Card>

      {/* YAML Display */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base">Workflow YAML File</CardTitle>
            <CardDescription>
              Copy this YAML file to your <code className="text-xs">.github/workflows/</code> directory
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
                Copy YAML
              </>
            )}
          </Button>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px] w-full rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-4">
            <pre className="text-xs font-mono text-zinc-900 dark:text-zinc-100 whitespace-pre-wrap">
              {yamlContent}
            </pre>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

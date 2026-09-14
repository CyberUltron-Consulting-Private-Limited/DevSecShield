"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Copy, Check } from "lucide-react";
import { toast } from "sonner";
import { ScrollArea } from "@/components/ui/scroll-area";
import { listDASTProfiles } from "@/utils/backend_api";

export function JenkinsDastGuide({ teamId }: { apiKey: string; teamId: number }) {
  const [copied, setCopied] = useState(false);
  const [profileId, setProfileId] = useState<string>("");
  const profiles = useQuery({
    queryKey: ["dast-profiles", teamId],
    queryFn: () => listDASTProfiles(teamId),
    enabled: Number.isFinite(teamId),
  });

  const selected = profileId || (profiles.data?.[0] ? String(profiles.data[0].id) : "");

  const jenkinsfile = useMemo(() => {
    const id = selected || "DAST_PROFILE_ID";
    return `pipeline {
    agent any

    environment {
        CICD_API_KEY = credentials('CICD_API_KEY')
        DAST_API_URL = 'https://devsecshieldapi.zeroshield.ai/cicd/dast/scan'
        DAST_PROFILE_ID = '${id}'
    }

    stages {
        stage('Deploy') {
            steps {
                echo 'Deploy the application to the staging URL this DAST profile targets.'
            }
        }

        stage('DAST fire-and-forget') {
            steps {
                script {
                    def profileId = env.DAST_PROFILE_ID
                    if (!profileId?.trim()) {
                        error('Set DAST_PROFILE_ID on the Jenkins job (saved DevSecShield DAST profile id).')
                    }
                    def payload = "{\\"profile_id\\": \${profileId}}"
                    def response = sh(script: """
                        curl -sS -X POST \\\\
                          -H "cicd-api-key: \${env.CICD_API_KEY}" \\\\
                          -H "Content-Type: application/json" \\\\
                          -d '\${payload}' \\\\
                          "\${env.DAST_API_URL}"
                    """, returnStdout: true).trim()
                    echo "DAST dispatch: \${response}"
                    def jsonResponse = readJSON(text: response)
                    if (!jsonResponse.scan_id) {
                        error("DAST dispatch did not return scan_id: \${response}")
                    }
                    env.DAST_SCAN_ID = jsonResponse.scan_id.toString()
                }
            }
        }
    }
}
`;
  }, [selected]);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(jenkinsfile);
      setCopied(true);
      toast.success("DAST Jenkinsfile copied");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy Jenkinsfile");
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">Jenkins DAST after deploy</h3>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          Use the API key from this DAST integration. A SAST key on{" "}
          <code className="font-mono text-xs">/cicd/dast/scan</code> returns 403. No zip. Pick a saved DAST
          profile; the pipeline POSTs JSON. Existing Jenkinsfiles that still use a SAST key for DAST must
          switch to this key. To open one Jira Task per finding when the scan succeeds, save a Jira project ID
          and enable auto-create on this DAST CI/CD integration (Ticketing settings).
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">DAST profile</CardTitle>
          <CardDescription>This fills DAST_PROFILE_ID in the Jenkinsfile below.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <Label>Saved profile</Label>
          <Select value={selected || undefined} onValueChange={setProfileId}>
            <SelectTrigger id="dast-cicd-profile" className="cursor-pointer">
              <SelectValue placeholder={profiles.isLoading ? "Loading profiles…" : "Select a DAST profile"} />
            </SelectTrigger>
            <SelectContent>
              {(profiles.data ?? []).map((profile) => (
                <SelectItem key={profile.id} value={String(profile.id)}>
                  #{profile.id} {profile.title}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {(!profiles.data || profiles.data.length === 0) && !profiles.isLoading && (
            <p className="text-xs text-zinc-500">Create a profile on the Scan settings tab first.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base">DAST Jenkinsfile</CardTitle>
            <CardDescription>Store the API key as Jenkins credential ID CICD_API_KEY.</CardDescription>
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
                Copy Jenkinsfile
              </>
            )}
          </Button>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[420px] w-full rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-4">
            <pre className="text-xs font-mono text-zinc-900 dark:text-zinc-100 whitespace-pre-wrap">{jenkinsfile}</pre>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

"use client";

import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";
import { toast } from "sonner";
import { ScrollArea } from "@/components/ui/scroll-area";

interface JenkinsIntegrationGuideProps {
  apiKey: string;
}

export function JenkinsGuide({ apiKey }: JenkinsIntegrationGuideProps) {
  const [copied, setCopied] = useState(false);

  // Helper function to mask API key (show first 4 and last 4 characters)
  const maskApiKey = (key: string) => {
    if (key.length <= 8) {
      return "•".repeat(key.length);
    }
    const start = key.substring(0, 4);
    const end = key.substring(key.length - 4);
    return `${start}${"•".repeat(12)}${end}`;
  };

  // Generate Jenkinsfile content based on selections (full content for copying)
  const jenkinsfileContent = useMemo(() => {
    // Escape $ to prevent template literal interpolation
    const dollar = '$';
    return `pipeline {
    agent any

    environment {
        CICD_API_KEY = '${apiKey}'
        SAST_API_URL = 'https://devsecshieldapi.zeroshield.ai/cicd/sast/scan'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                script {
                    sh 'rm -rf venv'
                    sh 'rm -rf project.zip'
                    sh 'rm -rf *.json'
                    sh 'rm -rf *.csv'
                    sh 'rm -rf *.sh'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                script {
                    sh 'rm -rf project_folder'
                    sh 'mkdir project_folder'
                    sh 'find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;'
                    sh 'zip -r project.zip project_folder'
                }
            }
        }


        stage('Perform SAST Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST                         -H "cicd-api-key: ${dollar}{CICD_API_KEY}"                         -F "zip_file=@project.zip"                         "${dollar}{SAST_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def vulnerabilities = jsonResponse.vulnerabilities

                    echo "Vulnerabilities found during SAST:"
                    echo "${dollar}{vulnerabilities}"

                    env.VULNERABILITIES = vulnerabilities.toString()
                }
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}`;
  }, [apiKey]);

  // Generate masked Jenkinsfile content for display
  const displayedJenkinsfileContent = useMemo(() => {
    const maskedKey = maskApiKey(apiKey);
    // Escape $ to prevent template literal interpolation
    const dollar = '$';
    return `pipeline {
    agent any

    environment {
        CICD_API_KEY = '${maskedKey}'
        SAST_API_URL = 'https://devsecshieldapi.zeroshield.ai/cicd/sast/scan'
    }

    stages {
        stage('Clean Up Old Files') {
            steps {
                script {
                    sh 'rm -rf venv'
                    sh 'rm -rf project.zip'
                    sh 'rm -rf *.json'
                    sh 'rm -rf *.csv'
                    sh 'rm -rf *.sh'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Create ZIP Files') {
            steps {
                script {
                    sh 'rm -rf project_folder'
                    sh 'mkdir project_folder'
                    sh 'find . -maxdepth 1 -not -name "." -not -name ".." -not -name ".git" -not -name "venv" -not -name "project_folder" -exec mv {} project_folder/ \\;'
                    sh 'zip -r project.zip project_folder'
                }
            }
        }


        stage('Perform SAST Scan') {
            steps {
                script {
                    def response = sh(script: """
                        #!/bin/bash
                        curl -v -X POST                         -H "cicd-api-key: ${dollar}{CICD_API_KEY}"                         -F "zip_file=@project.zip"                         "${dollar}{SAST_API_URL}"
                    """, returnStdout: true).trim()

                    def jsonResponse = readJSON(text: response)
                    def vulnerabilities = jsonResponse.vulnerabilities

                    echo "Vulnerabilities found during SAST:"
                    echo "${dollar}{vulnerabilities}"

                    env.VULNERABILITIES = vulnerabilities.toString()
                }
            }
        }

        // Additional stages (e.g., deploy) can be added here
    }
}`;
  }, [apiKey]);

  const copyToClipboard = async () => {
    try {
      // Copy the full content with unmasked API key
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
          Follow these steps to integrate DevSecShield SAST scanning into your Jenkins pipeline.
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
              Note: The API key is included in the Jenkinsfile. For enhanced security, you can use Jenkins credentials instead:
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
                  Paste your API key in the <strong>Secret</strong> field: <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">{apiKey.substring(0, 20)}...</code>
                </li>
                <li>
                  Click <strong>OK</strong> to save
                </li>
                <li>
                  Update the Jenkinsfile environment section to use credentials:
                  <div className="mt-2 p-2 bg-zinc-50 dark:bg-zinc-800 rounded border border-zinc-200 dark:border-zinc-700">
                    <p className="text-xs font-mono text-zinc-900 dark:text-zinc-100 break-all">
                      <code className="text-xs">CICD_API_KEY = credentials('CICD_API_KEY')</code>
                    </p>
                  </div>
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
              Run the pipeline. The SAST scan will execute automatically as part of the pipeline.
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
              {displayedJenkinsfileContent}
            </pre>
          </ScrollArea>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">DAST after deploy</CardTitle>
          <CardDescription>
            Trigger a saved DAST profile (no zip). Store the API key as Jenkins credentials ID{" "}
            <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">CICD_API_KEY</code>
            {" "}and set job env <code className="bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded text-xs font-mono">DAST_PROFILE_ID</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <p className="text-sm font-medium mb-2">Default: fire-and-forget</p>
            <pre className="text-xs font-mono whitespace-pre-wrap rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-3">{`environment {
    CICD_API_KEY = credentials('CICD_API_KEY')
    DAST_API_URL = 'https://devsecshieldapi.zeroshield.ai/cicd/dast/scan'
}
stage('DAST after Deploy') {
    steps {
        sh '''
          curl -sS -X POST \\
            -H "cicd-api-key: $CICD_API_KEY" \\
            -H "Content-Type: application/json" \\
            -d "{\\"profile_id\\": $DAST_PROFILE_ID}" \\
            "$DAST_API_URL"
        '''
    }
}`}</pre>
          </div>
          <div>
            <p className="text-sm font-medium mb-2">Optional: wait-and-gate (fail on High/Critical)</p>
            <pre className="text-xs font-mono whitespace-pre-wrap rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 p-3">{`timeout(time: 30, unit: 'MINUTES') {
    waitUntil {
        def body = readJSON(text: sh(script: '''
          curl -sS -H "cicd-api-key: $CICD_API_KEY" \\
            "$DAST_API_URL/$DAST_SCAN_ID"
        ''', returnStdout: true).trim())
        if (body.status == 'failure') { error('DAST scan failed') }
        if (body.status == 'success' && body.gate_failed) { error('High/Critical DAST findings') }
        return body.status == 'success'
    }
}`}</pre>
          </div>
          <p className="text-xs text-zinc-500">
            Full sample: <code className="font-mono">cicd_workflow_files/Jenkinsfile.dast</code>
          </p>
        </CardContent>
      </Card>
    </div>
  );
}


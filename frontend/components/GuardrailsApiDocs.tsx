"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BookOpen } from "lucide-react";

export default function GuardrailsApiDocs() {
  return (
    <div className="space-y-6">
      {/* Overview Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BookOpen className="w-5 h-5" />
            API Overview
          </CardTitle>
          <CardDescription>
            Public REST API for Guardrails Integration
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">Base URL</h3>
            <code className="block bg-zinc-100 dark:bg-zinc-800 px-4 py-2 rounded text-sm font-mono text-zinc-900 dark:text-zinc-100">
              https://devsecshieldapi.zeroshield.ai
            </code>
          </div>
          
          <div>
            <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">Authentication</h3>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-3">
              All API requests require authentication using an API key. Include your API key in the request header:
            </p>
            <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded">
              <code className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
                gr-api-key: Bearer {"{"}your_api_key{"}"}
              </code>
            </div>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-2">
              Your API key can be found above in the dashboard header. Copy it using the copy button.
            </p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-zinc-900 dark:text-white mb-2">Response Format</h3>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-2">
              All responses are returned in JSON format. Successful responses will have a 200 status code, while errors will return appropriate HTTP status codes (400, 401, 404, 500, etc.).
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Start Scan Endpoint */}
      <Card>
        <CardHeader>
          <CardTitle>Start Guardrails Scan</CardTitle>
          <CardDescription>
            Initiate a new guardrails scan for an input prompt
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Badge className="bg-green-500 hover:bg-green-600">POST</Badge>
              <code className="text-sm font-mono bg-zinc-100 dark:bg-zinc-800 px-2 py-1 rounded">
                /public/guardrails/start_scan
              </code>
            </div>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-2">
              Starts a new guardrails scan for the provided input prompt. Returns a scan ID that can be used to check the status and retrieve results.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">Request Body</h4>
            <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
              <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`{
  "input_prompt": "string"
}`}
              </pre>
            </div>
            <div className="mt-2 space-y-1">
              <p className="text-sm font-medium text-zinc-900 dark:text-white">Parameters:</p>
              <ul className="text-sm text-zinc-600 dark:text-zinc-400 ml-4 list-disc">
                <li><code className="bg-zinc-200 dark:bg-zinc-700 px-1 rounded">input_prompt</code> (required): The prompt text to be scanned by guardrails</li>
              </ul>
            </div>
          </div>

          <div>
            <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">Response</h4>
            <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
              <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`{
  "result_id": "507f1f77bcf86cd799439011",
  "status": "pending"
}`}
              </pre>
            </div>
            <div className="mt-2 space-y-1">
              <p className="text-sm font-medium text-zinc-900 dark:text-white">Response Fields:</p>
              <ul className="text-sm text-zinc-600 dark:text-zinc-400 ml-4 list-disc">
                <li><code className="bg-zinc-200 dark:bg-zinc-700 px-1 rounded">result_id</code>: MongoDB ObjectId string that can be used to check scan status</li>
                <li><code className="bg-zinc-200 dark:bg-zinc-700 px-1 rounded">status</code>: Current status of the scan (pending, started, success, failed)</li>
              </ul>
            </div>
          </div>

          <div>
            <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">Example Request</h4>
            <div className="space-y-2">
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">cURL</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`curl -X POST "https://devsecshieldapi.zeroshield.ai/public/guardrails/start_scan" \\
  -H "gr-api-key: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "input_prompt": "What is the weather today?"
  }'`}
                  </pre>
                </div>
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">Python</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`import requests

url = "https://devsecshieldapi.zeroshield.ai/public/guardrails/start_scan"
headers = {
    "gr-api-key": "Bearer YOUR_API_KEY",
    "Content-Type": "application/json"
}
data = {
    "input_prompt": "What is the weather today?"
}

response = requests.post(url, headers=headers, json=data)
result = response.json()
print(result)`}
                  </pre>
                </div>
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">JavaScript</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`const response = await fetch("https://devsecshieldapi.zeroshield.ai/public/guardrails/start_scan", {
  method: "POST",
  headers: {
    "gr-api-key": "Bearer YOUR_API_KEY",
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    input_prompt: "What is the weather today?"
  })
});

const result = await response.json();
console.log(result);`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Get Scan Status Endpoint */}
      <Card>
        <CardHeader>
          <CardTitle>Get Scan Status</CardTitle>
          <CardDescription>
            Retrieve the status and results of a guardrails scan
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Badge className="bg-blue-500 hover:bg-blue-600">GET</Badge>
              <code className="text-sm font-mono bg-zinc-100 dark:bg-zinc-800 px-2 py-1 rounded">
                /public/guardrails/{"{"}scan_id{"}"}
              </code>
            </div>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-2">
              Retrieves the current status of a guardrails scan. If the scan has completed successfully, the results will also be included in the response.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">Path Parameters</h4>
            <div className="space-y-1">
              <ul className="text-sm text-zinc-600 dark:text-zinc-400 ml-4 list-disc">
                <li><code className="bg-zinc-200 dark:bg-zinc-700 px-1 rounded">scan_id</code> (required): The MongoDB ObjectId returned from the start_scan endpoint</li>
              </ul>
            </div>
          </div>

          <div>
            <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">Response</h4>
            <div className="space-y-3">
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">Success Response (Scan Complete)</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`{
  "status": "success",
  "results": {
    "sanitized_prompt": "What is the weather today?",
    "check_passed": true,
    "anonymize_context": { ... },
    "toxicity_context": { ... },
    "tokenlimit_context": { ... },
    "promptinjection_context": { ... },
    "regex_context": { ... },
    "code_context": { ... },
    "secrets_context": { ... }
  }
}`}
                  </pre>
                </div>
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">Pending/In Progress Response</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`{
  "status": "pending",
  "results": null
}`}
                  </pre>
                </div>
              </div>
            </div>
            <div className="mt-2 space-y-1">
              <p className="text-sm font-medium text-zinc-900 dark:text-white">Response Fields:</p>
              <ul className="text-sm text-zinc-600 dark:text-zinc-400 ml-4 list-disc">
                <li><code className="bg-zinc-200 dark:bg-zinc-700 px-1 rounded">status</code>: Current status (pending, started, success, failed, not_started)</li>
                <li><code className="bg-zinc-200 dark:bg-zinc-700 px-1 rounded">results</code>: Scan results object (null if scan is not complete). Contains sanitized_prompt and metadata from all guardrail contexts</li>
              </ul>
            </div>
          </div>

          <div>
            <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">Example Request</h4>
            <div className="space-y-2">
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">cURL</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`curl -X GET "https://devsecshieldapi.zeroshield.ai/public/guardrails/507f1f77bcf86cd799439011" \\
  -H "gr-api-key: Bearer YOUR_API_KEY"`}
                  </pre>
                </div>
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">Python</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`import requests

scan_id = "507f1f77bcf86cd799439011"
url = f"https://devsecshieldapi.zeroshield.ai/public/guardrails/\${scan_id}"
headers = {
    "gr-api-key": "Bearer YOUR_API_KEY"
}

response = requests.get(url, headers=headers)
result = response.json()
print(result)`}
                  </pre>
                </div>
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">JavaScript</p>
                <div className="bg-zinc-100 dark:bg-zinc-800 px-4 py-3 rounded overflow-x-auto">
                  <pre className="text-sm font-mono text-zinc-900 dark:text-zinc-100">
{`const scanId = "507f1f77bcf86cd799439011";
const response = await fetch(
  \`https://devsecshieldapi.zeroshield.ai/public/guardrails/\${scanId}\`,
  {
    headers: {
      "gr-api-key": "Bearer YOUR_API_KEY"
    }
  }
);

const result = await response.json();
console.log(result);`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Error Handling Section */}
      <Card>
        <CardHeader>
          <CardTitle>Error Handling</CardTitle>
          <CardDescription>
            Common error responses and status codes
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">400 Bad Request</h4>
              <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-2">
                Returned when the request is malformed or missing required parameters.
              </p>
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 px-4 py-3 rounded">
                <pre className="text-sm font-mono text-red-900 dark:text-red-100">
{`{
  "detail": "Invalid scan ID"
}`}
                </pre>
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">401 Unauthorized</h4>
              <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-2">
                Returned when the API key is missing, invalid, or expired.
              </p>
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 px-4 py-3 rounded">
                <pre className="text-sm font-mono text-red-900 dark:text-red-100">
{`{
  "detail": "Missing or invalid Guardrails API key"
}`}
                </pre>
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">404 Not Found</h4>
              <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-2">
                Returned when the requested resource (scan ID or integration) is not found.
              </p>
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 px-4 py-3 rounded">
                <pre className="text-sm font-mono text-red-900 dark:text-red-100">
{`{
  "detail": "Guardrails log not found"
}`}
                </pre>
              </div>
            </div>

            <div>
              <h4 className="font-semibold text-zinc-900 dark:text-white mb-2">500 Internal Server Error</h4>
              <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-2">
                Returned when an unexpected server error occurs.
              </p>
              <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 px-4 py-3 rounded">
                <pre className="text-sm font-mono text-red-900 dark:text-red-100">
{`{
  "detail": "Error starting guardrails scan"
}`}
                </pre>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Best Practices Section */}
      <Card>
        <CardHeader>
          <CardTitle>Best Practices</CardTitle>
          <CardDescription>
            Recommendations for using the API effectively
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2 text-sm text-zinc-600 dark:text-zinc-400">
            <li className="flex items-start gap-2">
              <span className="text-teal-600 dark:text-teal-400 mt-1">•</span>
              <span><strong className="text-zinc-900 dark:text-white">Polling Strategy:</strong> After starting a scan, poll the status endpoint every 1-2 seconds until the status is "success" or "failed".</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-teal-600 dark:text-teal-400 mt-1">•</span>
              <span><strong className="text-zinc-900 dark:text-white">API Key Security:</strong> Never expose your API key in client-side code or public repositories. Store it securely in environment variables or secure vaults.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-teal-600 dark:text-teal-400 mt-1">•</span>
              <span><strong className="text-zinc-900 dark:text-white">Error Handling:</strong> Always implement proper error handling for network failures, timeouts, and API errors.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-teal-600 dark:text-teal-400 mt-1">•</span>
              <span><strong className="text-zinc-900 dark:text-white">Rate Limiting:</strong> Be mindful of rate limits. Implement exponential backoff for retries.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-teal-600 dark:text-teal-400 mt-1">•</span>
              <span><strong className="text-zinc-900 dark:text-white">Timeout Handling:</strong> Set appropriate timeouts for API requests. Scans may take several seconds to complete.</span>
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}


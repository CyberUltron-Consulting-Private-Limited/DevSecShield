/**
 * Issue #31: the one line a failed API call may write to the browser console. It names the request by method, URL
 * path and status (or axios's error code when no response came) and reads nothing else of it: not the body
 * (config.data), the headers (the bearer token), the params, the query string, the fragment or the origin.
 * Failing-first on origin/dev bbe3cfef: safeRequestLog.ts did not exist (handleApiError logged the whole AxiosError).
 * Run: npx --yes tsx@4.23.15 utils/safeRequestLog.test.ts
 */
import assert from "node:assert/strict";
import test from "node:test";
import { AxiosError, AxiosHeaders, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { describeFailedRequest, logFailedRequest } from "./safeRequestLog";

// Fabricated values: none may appear in the line.
const bodyMarker = "request-body-marker-31";
const headerMarker = "request-header-marker-31";

function failed(request: { method: string; url: string }, status?: number, code?: string): AxiosError {
  const config: InternalAxiosRequestConfig = {
    ...request,
    headers: new AxiosHeaders({ Authorization: `Bearer ${headerMarker}` }),
    params: { code: bodyMarker },
    data: JSON.stringify({ current_password: bodyMarker, new_password: `${bodyMarker}-new` }),
  };
  const response: AxiosResponse | undefined = status === undefined ? undefined
    : { status, statusText: "Refused", headers: {}, config, data: { detail: bodyMarker } };
  return new AxiosError("Request failed", code, config, { _body: config.data }, response);
}

test("a refused request is named by its method, path and status, nothing else", () => {
  const line = describeFailedRequest(failed({ method: "post", url: "/account/password" }, 400, "ERR_BAD_REQUEST"));
  assert.equal(line, "POST /account/password, status 400");
  assert.ok(!line.includes(bodyMarker) && !line.includes(headerMarker) && !line.includes("Bearer"));
});

test("the URL keeps only its path: no origin, credentials, query string or fragment", () => {
  const absolute = `https://someone:${bodyMarker}@api.example.test/7/cbom/sources?code=${bodyMarker}#${bodyMarker}`;
  assert.equal(describeFailedRequest(failed({ method: "get", url: absolute }, 404)), "GET /7/cbom/sources, status 404");
  assert.equal(describeFailedRequest(failed({ method: "delete", url: `/7/scan/12?code=${bodyMarker}` }, 409)),
    "DELETE /7/scan/12, status 409");
});

test("a request that got no response is named with axios's error code", () => {
  const request = { method: "post", url: "/login" };
  assert.equal(describeFailedRequest(failed(request, undefined, AxiosError.ERR_NETWORK)),
    "POST /login, no response (ERR_NETWORK)");
  assert.equal(describeFailedRequest(failed(request, undefined, AxiosError.ECONNABORTED)),
    "POST /login, no response (ECONNABORTED)");
  assert.equal(describeFailedRequest(failed(request)), "POST /login, no response");
});

test("an error without request details is still described, never thrown on", () => {
  assert.equal(describeFailedRequest(new AxiosError("Network Error", AxiosError.ERR_NETWORK)),
    "REQUEST (no URL), no response (ERR_NETWORK)");
});

test("logFailedRequest writes that line as one console.warn string", () => {
  const calls: unknown[][] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => void calls.push(args);
  try {
    logFailedRequest(failed({ method: "post", url: "/account/password" }, 400));
  } finally {
    console.warn = original;
  }
  assert.deepEqual(calls, [["API request failed: POST /account/password, status 400"]]);
});

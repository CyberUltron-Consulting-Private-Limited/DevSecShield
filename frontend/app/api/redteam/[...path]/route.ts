import { NextRequest, NextResponse } from "next/server";

const REDAMON_API_URL =
  process.env.REDAMON_API_URL || "http://localhost:3000";

/**
 * Catch-all proxy: forwards /api/redteam/* → RedAmon webapp /api/*
 * Passes X-DSS-Team-Id header so RedAmon can scope data per team.
 */
async function proxyRequest(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const teamId = req.headers.get("x-team-id");
  if (!teamId) {
    return NextResponse.json(
      { error: "Missing X-Team-Id header" },
      { status: 401 }
    );
  }

  const { path } = await params;
  const targetPath = `/api/${path.join("/")}`;
  const url = new URL(targetPath, REDAMON_API_URL);

  const incomingParams = req.nextUrl.searchParams;
  incomingParams.forEach((value, key) => url.searchParams.set(key, value));

  const headers = new Headers();
  const contentType = req.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  headers.set("accept", req.headers.get("accept") || "application/json");
  headers.set("x-dss-team-id", teamId);

  const isSSE = req.headers.get("accept") === "text/event-stream";

  const fetchOptions: RequestInit = {
    method: req.method,
    headers,
  };

  if (req.method !== "GET" && req.method !== "HEAD") {
    fetchOptions.body = await req.arrayBuffer();
  }

  const response = await fetch(url.toString(), fetchOptions);

  if (isSSE) {
    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      },
    });
  }

  const responseHeaders = new Headers();
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() !== "transfer-encoding") {
      responseHeaders.set(key, value);
    }
  });

  const body = await response.arrayBuffer();

  return new NextResponse(body, {
    status: response.status,
    headers: responseHeaders,
  });
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const PATCH = proxyRequest;
export const DELETE = proxyRequest;

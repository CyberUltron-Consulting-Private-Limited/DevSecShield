"use client";

// Add scan node: the scan node as downloads from this ZeroShield server (backend routers/cbom_node_artifacts.py).
// Customers have no repository access and no ZeroShield registry, so the image file, the Helm chart and the OVA/AMI
// Packer build kits come from here. A download asks the server for a short-lived link and lets the browser fetch it
// (straight to disk, with its progress). A file the server does not hold is a disabled button with the server's
// sentence ("... is not available on this server yet. Contact your administrator."). Rendered by nodeDownloads.test.ts.

import { useMutation } from "@tanstack/react-query";
import { Download, Loader2 } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { getCbomNodeArtifactLink } from "@/utils/backend_api";
import { apiBaseURL } from "@/utils/interceptors";

import {
  KIT_STEPS,
  downloadKinds,
  downloadLabel,
  notAvailable,
  refusalReason,
  type DeployMethod,
  type NodeArtifact,
  type NodeArtifacts,
} from "./logic";

function startDownload(url: string) {
  // The response is an attachment (Content-Disposition), so the page stays where it is.
  const a = document.createElement("a");
  a.href = `${String(apiBaseURL).replace(/\/$/, "")}${url}`;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

export function NodeDownloads({
  teamId,
  method,
  artifacts,
  loading,
  error,
}: {
  teamId: number;
  method: DeployMethod;
  artifacts: NodeArtifacts | undefined;
  loading?: boolean;
  error?: unknown;
}) {
  const [failed, setFailed] = useState<string | null>(null);
  const link = useMutation({
    mutationFn: (kind: string) => getCbomNodeArtifactLink(teamId, kind),
    onSuccess: (data) => {
      setFailed(null);
      startDownload(data.url);
    },
    onError: (err) => setFailed(refusalReason(err) ?? "The download could not be started. Try again."),
  });
  const byKind = (kind: NodeArtifact["kind"]) => artifacts?.artifacts.find((a) => a.kind === kind) ?? null;
  const image = byKind("image");
  const kit = method === "ova" || method === "ami" ? method : null;

  return (
    <div className="mt-4 space-y-3 rounded-lg border p-3" data-testid="node-downloads">
      <p className="text-sm font-medium text-zinc-900 dark:text-white">
        Downloads{artifacts?.version ? ` (scan node ${artifacts.version})` : ""}
      </p>
      {loading && !artifacts ? (
        <p className="text-xs text-zinc-500">Checking which downloads this server offers…</p>
      ) : error && !artifacts ? (
        <p className="text-xs text-red-600" role="alert">
          Could not check the downloads: {refusalReason(error) ?? "try again later"}.
        </p>
      ) : (
        <ul className="space-y-2">
          {downloadKinds(method).map((kind) => {
            const a = byKind(kind);
            const ok = !!a?.available;
            return (
              <li key={kind} className="space-y-1" data-testid={`node-download-${kind}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant={kind === downloadKinds(method)[0] ? "default" : "outline"}
                    size="sm"
                    className="cursor-pointer"
                    disabled={!ok || link.isPending}
                    title={a?.sha256 ? `SHA-256 ${a.sha256}` : undefined}
                    onClick={() => link.mutate(kind)}
                  >
                    {link.isPending && link.variables === kind ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Download className="h-4 w-4 mr-2" />
                    )}
                    {downloadLabel(kind, a)}
                  </Button>
                  {kind === "image" && ok && (
                    <Button variant="ghost" size="sm" className="cursor-pointer" disabled={link.isPending}
                      onClick={() => link.mutate("image-sha256")}>
                      .sha256
                    </Button>
                  )}
                </div>
                {ok && a?.sha256 && (
                  <p className="text-xs text-zinc-500 break-all">
                    {a.filename} · SHA-256 <span className="font-mono">{a.sha256}</span>
                  </p>
                )}
                {!ok && (
                  <p className="text-xs text-amber-700 dark:text-amber-400" data-testid="node-download-unavailable">
                    {notAvailable(kind, a)}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {kit && (
        <ol className="list-decimal pl-5 space-y-1 text-xs text-zinc-600 dark:text-zinc-400" data-testid={`node-kit-steps-${kit}`}>
          {KIT_STEPS[kit].map((step) => <li key={step}>{step}</li>)}
        </ol>
      )}
      {method === "docker" && image?.available && (
        <p className="text-xs text-zinc-600 dark:text-zinc-400">
          Copy the image file and its .sha256 to the host; the command shown after you create the node checks and
          loads it, then runs it.
        </p>
      )}
      {failed && <p className="text-xs text-red-600" role="alert">{failed}</p>}
    </div>
  );
}

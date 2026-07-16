"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Download, Loader2, ScanLine, Smartphone, Eye } from "lucide-react";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import {
  estimateCreditsForScan,
  getMobileExportResults,
  startScan,
  type MobileConversationResponse,
  type StartScanPayload,
} from "@/utils/backend_api";
import { toast } from "sonner";
import { useParams, useRouter } from "next/navigation";
import { showErrorToast } from "@/utils/error-handler";

const ACCEPTED = ".apk,.ipa,.xapk,.apks,.aab";

export function MobileOptionsSidebar({
  query,
}: {
  query: UseQueryResult<MobileConversationResponse>;
}) {
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [estimatedCredits, setEstimatedCredits] = useState<number | null>(null);
  const [estimationDone, setEstimationDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const queryClient = useQueryClient();
  const router = useRouter();
  const params = useParams();
  const team_id = parseInt(params?.team_id as string, 10);
  const scan_id = parseInt(params?.scan_id as string, 10);

  const scanStatus = query.data?.scan_status;
  const isDone = scanStatus === "success";
  const isInProgress = scanStatus === "pending" || scanStatus === "started";
  const isFailed = scanStatus === "failure";

  const buildPayload = (): StartScanPayload => ({
    mobile: {
      apk_file_used: true,
      file_name: uploadedFile?.name ?? null,
    },
  });

  const estimateMutation = useMutation({
    mutationFn: async () => {
      if (!uploadedFile) throw new Error("Upload a mobile app binary first");
      const payload = JSON.stringify(buildPayload());
      return estimateCreditsForScan(team_id, "mobile", scan_id, payload, uploadedFile);
    },
    onSuccess: (data) => {
      setEstimatedCredits(data.credits_required);
      setEstimationDone(true);
      toast.success(`Estimated ${data.credits_required} credits`);
    },
    onError: (error) => showErrorToast(error, "Credit estimation failed"),
  });

  const startMutation = useMutation({
    mutationFn: async () => {
      if (!uploadedFile) throw new Error("Upload a mobile app binary first");
      setBusy(true);
      const payload = JSON.stringify(buildPayload());
      return startScan(team_id, "mobile", scan_id, payload, uploadedFile);
    },
    onSuccess: () => {
      setBusy(false);
      queryClient.invalidateQueries({ queryKey: ["mobile-conversation-data", team_id, scan_id] });
      toast.success("Mobile App Security scan started");
    },
    onError: (error) => {
      setBusy(false);
      showErrorToast(error, "Failed to start scan");
    },
  });

  const exportMutation = useMutation({
    mutationFn: () => getMobileExportResults(team_id, scan_id),
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mobile-security-report-${scan_id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    },
    onError: (error) => showErrorToast(error, "Export failed"),
  });

  return (
    <aside className="w-80 border-l border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 flex flex-col h-screen">
      <div className="p-4 border-b border-zinc-200 dark:border-zinc-800">
        <div className="flex items-center gap-2">
          <Smartphone className="size-5 text-blue-600" />
          <h2 className="font-semibold text-sm">Mobile App Security</h2>
        </div>
        <p className="text-xs text-zinc-500 mt-1">Upload an APK or IPA for static analysis</p>
      </div>

      <ScrollArea className="flex-1 p-4">
        {!isDone && !isInProgress && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="mobile-binary">App binary</Label>
              <Input
                id="mobile-binary"
                type="file"
                accept={ACCEPTED}
                disabled={busy || estimateMutation.isPending || startMutation.isPending}
                onChange={(e) => {
                  const file = e.target.files?.[0] ?? null;
                  setUploadedFile(file);
                  setEstimationDone(false);
                  setEstimatedCredits(null);
                }}
              />
              {uploadedFile && (
                <p className="text-xs text-zinc-500 truncate">{uploadedFile.name}</p>
              )}
            </div>

            <Separator />

            {!estimationDone ? (
              <Button
                className="w-full"
                variant="outline"
                disabled={!uploadedFile || estimateMutation.isPending}
                onClick={() => estimateMutation.mutate()}
              >
                {estimateMutation.isPending ? (
                  <Loader2 className="size-4 animate-spin mr-2" />
                ) : (
                  <ScanLine className="size-4 mr-2" />
                )}
                Estimate credits
              </Button>
            ) : (
              <div className="space-y-3">
                <p className="text-sm text-zinc-600 dark:text-zinc-400">
                  Credits required: <span className="font-semibold">{estimatedCredits}</span>
                </p>
                <Button
                  className="w-full"
                  disabled={!uploadedFile || startMutation.isPending || busy}
                  onClick={() => startMutation.mutate()}
                >
                  {startMutation.isPending || busy ? (
                    <Loader2 className="size-4 animate-spin mr-2" />
                  ) : (
                    <ScanLine className="size-4 mr-2" />
                  )}
                  Start scan
                </Button>
              </div>
            )}
          </div>
        )}

        {isInProgress && (
          <div className="flex flex-col items-center gap-3 py-8 text-center">
            <Loader2 className="size-8 animate-spin text-blue-600" />
            <p className="text-sm text-zinc-600 dark:text-zinc-400">Scan in progress…</p>
            {query.data?.info?.current != null && (
              <p className="text-xs text-zinc-500">{Math.round(query.data.info.current)}%</p>
            )}
          </div>
        )}

        {isFailed && (
          <p className="text-sm text-red-600">Scan failed. Create a new scan to try again.</p>
        )}

        {isDone && (
          <div className="space-y-3">
            <Button
              className="w-full"
              variant="outline"
              onClick={() => router.push(`/${team_id}/mobile/${scan_id}/results`)}
            >
              <Eye className="size-4 mr-2" />
              View results
            </Button>
            <Button
              className="w-full"
              variant="secondary"
              disabled={exportMutation.isPending}
              onClick={() => exportMutation.mutate()}
            >
              {exportMutation.isPending ? (
                <Loader2 className="size-4 animate-spin mr-2" />
              ) : (
                <Download className="size-4 mr-2" />
              )}
              Download PDF
            </Button>
          </div>
        )}
      </ScrollArea>
    </aside>
  );
}

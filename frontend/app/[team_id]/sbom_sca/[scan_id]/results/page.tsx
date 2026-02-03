"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import SbomResults from "@/components/SbomResults";
import { getSCASBOMConversationMessages } from "@/utils/backend_api";

export default function SbomResultsPage() {
  const params = useParams();
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);

  if (!scan_id) {
    toast.error("Scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Scan id not found
        </p>
      </div>
    );
  }

  const query = useQuery({
    queryKey: ['sbom_sca-conversation-data', scan_id],
    queryFn: getSCASBOMConversationMessages,
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching SBOM results. Please try again later.
        </p>
      </div>
    );
  }

  if (query.isLoading) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <Loader2 className="size-10 animate-spin text-blue-600" />
      </div>
    );
  }

  // Extract SBOM results from the conversation data
  // The SBOM results should be in query.data.data
  const sbomData = query.data?.data;

  if (!sbomData || !sbomData.matches) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No SBOM results found for this scan.
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <SbomResults data={sbomData} conversationId={scan_id} />
    </div>
  );
}


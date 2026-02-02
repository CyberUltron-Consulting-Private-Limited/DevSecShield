"use client";

import { usePathname } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import ZAPResults from "@/components/ZAPResults";
import WapitiResults from "@/components/WapitiResults";
import { getDASTConversationMessages } from "@/utils/backend_api";

export default function DASTResultsPage() {
  const pathname = usePathname();
  // Path format: /home/dast/[conversation_id]/results
  const pathParts = pathname.split('/').filter(Boolean);
  const conversation_id = parseInt(pathParts[2] || '0');
  
  if (!conversation_id) {
    toast.error("Conversation id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Conversation id not found
        </p>
      </div>
    );
  }

  const query = useQuery({
    queryKey: ['dast-conversation-data', conversation_id],
    queryFn: getDASTConversationMessages,
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching DAST results. Please try again later.
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

  // Extract DAST results from the conversation data with fallbacks
  // The DAST results should be in query.data.data
  const dastData = query.data?.data;
  const authMode = query.data?.auth_mode  || null; // Check both possible field names

  // Handle empty or null data
  if (!dastData || (typeof dastData === 'object' && Object.keys(dastData).length === 0)) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No DAST results found for this conversation. The scan may not have completed yet.
        </p>
      </div>
    );
  }

  // Route to appropriate component based on auth_mode
  if (authMode === "form_based") {
    // ZAP results - should be an array of alerts
    const zapAlerts = Array.isArray(dastData) ? dastData : [];
    return (
      <div className="min-h-screen bg-white dark:bg-zinc-900">
        <ZAPResults data={zapAlerts} conversationId={conversation_id} />
      </div>
    );
  } else if (authMode === "header_cookie_based") {
    // Wapiti results - should be an object with classifications and vulnerabilities
    const wapitiData = typeof dastData === 'object' && !Array.isArray(dastData) 
      ? dastData as { classifications?: Record<string, any>; vulnerabilities?: Record<string, any[]> }
      : { classifications: {}, vulnerabilities: {} };
    
    // Ensure it has the correct structure
    const wapitiResults = {
      classifications: wapitiData.classifications || {},
      vulnerabilities: wapitiData.vulnerabilities || {}
    };
    
    return (
      <div className="min-h-screen bg-white dark:bg-zinc-900">
        <WapitiResults data={wapitiResults} conversationId={conversation_id} />
      </div>
    );
  } else {
    // Unknown auth mode - try to detect based on data structure
    if (Array.isArray(dastData)) {
      // Likely ZAP results (array)
      return (
        <div className="min-h-screen bg-white dark:bg-zinc-900">
          <ZAPResults data={dastData} conversationId={conversation_id} />
        </div>
      );
    } else if (dastData && typeof dastData === 'object' && ('classifications' in dastData || 'vulnerabilities' in dastData)) {
      // Likely Wapiti results (object with classifications and/or vulnerabilities)
      const wapitiResults = {
        classifications: (dastData as any).classifications || {},
        vulnerabilities: (dastData as any).vulnerabilities || {}
      };
      return (
        <div className="min-h-screen bg-white dark:bg-zinc-900">
          <WapitiResults data={wapitiResults} conversationId={conversation_id} />
        </div>
      );
    } else {
      return (
        <div className="flex h-screen w-full items-center justify-center">
          <p className="text-zinc-600 dark:text-zinc-400 mb-4">
            Unknown DAST result format. Auth mode: {authMode || "unknown"}
          </p>
        </div>
      );
    }
  }
}


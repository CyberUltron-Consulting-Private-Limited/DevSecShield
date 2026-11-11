"use client";

import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Github,
  GitBranch,
  GitCommit,
  ScanIcon,
  Download,
  Loader2,
  Eye,
} from "lucide-react";
import { Mode } from "@/utils/backend_api";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import { LeakageConversationResponse, startLeakageScan, getLeakageExportResults, reinitializeLeakageScan } from "@/utils/backend_api";
import { toast } from "@/utils/toast";
import { stateAfterError } from "@/utils/scanErrorRecovery";
import { useParams, useRouter } from "next/navigation";
// import { generateAndDownloadPDF } from "@/components/PDF_Report";

export function LeakageOptionsSidebar({
  query,
  mode,
  setMode,
  repo_url,
  setRepoUrl,
  PAT,
  setPAT,
}:{
  query: UseQueryResult<LeakageConversationResponse>;
  mode: Mode;
  setMode: Dispatch<SetStateAction<Mode>>;
  repo_url: string;
  setRepoUrl: Dispatch<SetStateAction<string>>;
  PAT: string;
  setPAT: Dispatch<SetStateAction<string>>;
}) {
  useEffect(() => {
    setMode(mode);
    setRepoUrl(repo_url);
    setPAT(PAT);
  }, [mode, repo_url, PAT]);

  const [ optionsSidebarState , setOptionsSidebarState ] = useState<"ready" | "scanning" | "error" | "done" >("ready");

  const handleStartScan = ({
    conversation_id,
    repo_url,
    PAT,
    mode
  }: {
    conversation_id: number;
    repo_url: string;
    PAT: string;
    mode: Mode;
  }) => {
    setOptionsSidebarState("scanning");
    if (mode === "unknown") {
      toast.error("Please select a repository platform");
      setOptionsSidebarState("error");
      throw new Error("Please select a repository platform");
    }
    return startLeakageScan({
      conversation_id,
      repo_url,
      PAT,
      mode
    });
  };

  const queryClient = useQueryClient();
  const router = useRouter();
  const { conversation_id } = useParams();
  const startScanMutation = useMutation({
    mutationFn: handleStartScan,
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ['leakage-conversation-data', parseInt(conversation_id as string)] });
    },
    onError: () => {
      setOptionsSidebarState("error");
    }
  });

  useEffect(() => {
    if (query.data?.scan_status === "success") {
      setOptionsSidebarState("done");
    }
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setOptionsSidebarState("scanning");
    }
    if (query.data?.scan_status === "failure") {
      setOptionsSidebarState("error");
    }
    if (query.data?.scan_status === "not_started" || !query.data?.scan_status) {
      setOptionsSidebarState("ready");
    }
  }, [query.data?.scan_status]);

  const exportMutation = useMutation({
    mutationFn: getLeakageExportResults,
    onSuccess: (data, variables , context) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);

      // download the pdf file
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title}_scan_report.pdf`;
      a.click();

      setOptionsSidebarState("done");
    },
    onError: () => {
      setOptionsSidebarState("error");
    }
  });

  const handleReinitializeScan = ({
    conversation_id,
    repo_url,
    PAT,
    mode
  }: {
    conversation_id: number;
    repo_url: string;
    PAT: string;
    mode: Mode;
  }) => {
    setOptionsSidebarState("ready");
    if (mode === "unknown") {
      toast.error("Please select a repository platform");
      setOptionsSidebarState("error");
      throw new Error("Please select a repository platform");
    }
    return reinitializeLeakageScan({
      conversation_id,
      repo_url,
      PAT,
      mode
    });
  };

  const reinitializeScanMutation = useMutation({
    mutationFn: handleReinitializeScan,
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ['leakage-conversation-data', parseInt(conversation_id as string)] });
    },
    onError: () => {
      setOptionsSidebarState("error");
    }
  });

  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">Leakage Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your Leakage scanning options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <>
          <div className="p-6">
            {/* Integration Inputs */}
            <div className="mb-8">
              <h3 className="text-sm font-semibold text-zinc-300 mb-4 flex flex-row items-center gap-2">
                Repository Selection <p className="text-red-500">*</p>
              </h3>
              <Accordion type="single" collapsible className="w-full">
                {/* GitHub Integration */}
                <AccordionItem value="github" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer">
                    <div className="flex items-center gap-2">
                      <Github className="h-4 w-4" />
                      <span>GitHub</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="pt-4 space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="github-repo-url" className="text-zinc-300">
                        Repository URL
                      </Label>
                      <Input
                        id="github-repo-url"
                        placeholder="https://github.com/username/repo"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        value={repo_url}
                        onChange={(e) => {
                          setRepoUrl(e.target.value);
                          setMode("github");
                        }}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="github-token" className="text-zinc-300">
                        Personal Access Token
                      </Label>
                      <Input
                        id="github-token"
                        type="password"
                        placeholder="Enter your GitHub token"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        value={PAT}
                        onChange={(e) => {
                          setPAT(e.target.value);
                        }}
                      />
                    </div>
                  </AccordionContent>
                </AccordionItem>

                {/* GitLab Integration */}
                <AccordionItem value="gitlab" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer">
                    <div className="flex items-center gap-2">
                      <GitBranch className="h-4 w-4" />
                      <span>GitLab</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="pt-4 space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="gitlab-repo-url" className="text-zinc-300">
                        Repository URL
                      </Label>
                      <Input
                        id="gitlab-repo-url"
                        placeholder="https://gitlab.com/username/repo"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        value={repo_url}
                        onChange={(e) => {
                          setRepoUrl(e.target.value);
                          setMode("gitlab");
                        }}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="gitlab-token" className="text-zinc-300">
                        Personal Access Token
                      </Label>
                      <Input
                        id="gitlab-token"
                        type="password"
                        placeholder="Enter your GitLab token"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        value={PAT}
                        onChange={(e) => {
                          setPAT(e.target.value);
                        }}
                      />
                    </div>
                  </AccordionContent>
                </AccordionItem>

                {/* Bitbucket Integration */}
                <AccordionItem value="bitbucket" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer">
                    <div className="flex items-center gap-2">
                      <GitCommit className="h-4 w-4" />
                      <span>Bitbucket</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="pt-4 space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="bitbucket-repo-url" className="text-zinc-300">
                        Repository URL
                      </Label>
                      <Input
                        id="bitbucket-repo-url"
                        placeholder="https://bitbucket.org/username/repo"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        value={repo_url}
                        onChange={(e) => {
                          setRepoUrl(e.target.value);
                          setMode("bitbucket");
                        }}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="bitbucket-token" className="text-zinc-300">
                        Personal Access Token
                      </Label>
                      <Input
                        id="bitbucket-token"
                        type="password"
                        placeholder="Enter your Bitbucket token"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        value={PAT}
                        onChange={(e) => {
                          setPAT(e.target.value);
                        }}
                      />
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </div>
          </div>
          <div className="p-6">
            <Button 
              variant="ghost" 
              size="icon-lg"
              onClick={() =>{ 
                startScanMutation.mutate({
                conversation_id: parseInt(conversation_id as string),
                repo_url,
                PAT,
                mode
              });
              setOptionsSidebarState("scanning");
              }}
              className="w-fit h-8 px-4 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white"
            >
              <ScanIcon className="size-4" />
              <span className="ml-1">Run Scan</span>
            </Button>
          </div>
        </>
      )}

      {optionsSidebarState === "scanning" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[400px]">
          <Loader2 className="h-8 w-8 text-blue-500 animate-spin mb-4" />
          <p className="text-zinc-300 text-center">
            Scan has started, this might take a while
          </p>
        </div>
      )}

      {optionsSidebarState === "done" && (
        <div className="p-6 space-y-4">
          <div className="flex flex-col items-center justify-center min-h-[200px] space-y-4">
            <p className="text-zinc-300 text-center">
              Scan has run successfully on the repository <span className="text-blue-500 mx-3 text-xs p-1 bg-zinc-800 rounded-md">{query.data?.repo_url}</span>
              You can now chat with your scan results
            </p>
            <Button 
              variant="ghost" 
              size="sm"
              onClick={() => {
                router.push(`/home/leakage/${conversation_id}/results?origin=chat`);
              }}
              className="w-full h-8 px-2 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white"
            >
              <Eye className="size-4" />
              <span className="ml-1">View Results</span>
            </Button>
            <Button 
              variant="ghost" 
              size="sm"
              onClick={async () => {
                exportMutation.mutate(parseInt(conversation_id as string));
              }}
              className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white"
            >
              <Download className="size-4" />
              <span className="ml-1">Download Scan Report</span>
            </Button>
          </div>
        </div>
      )}

      {optionsSidebarState === "error" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[200px] space-y-4">
          <p className="text-red-400 text-center">
            An error occurred during the scan. Please try again.
          </p>
          <Button 
            variant="ghost" 
            size="sm"
            data-testid="scan-try-again"
            onClick={() => {
              // back to the view that matches the scan, with the form still filled in (no reload)
              setOptionsSidebarState(stateAfterError(query.data?.scan_status));
              void query.refetch();
            }}
            className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white"
          >
            <span>Try again</span>
          </Button>
        </div>
      )}

      {query.data?.scan_status === "pending" && (
        <div className="p-6 border-t border-zinc-800">
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => {
              reinitializeScanMutation.mutate({
                conversation_id: parseInt(conversation_id as string),
                repo_url,
                PAT,
                mode
              });
            }}
            disabled={reinitializeScanMutation.isPending}
            className="w-full h-8 px-2 bg-yellow-600 hover:bg-yellow-700 text-white cursor-pointer hover:text-white disabled:opacity-50"
          >
            {reinitializeScanMutation.isPending ? (
              <>
                <Loader2 className="size-4 mr-2 animate-spin" />
                <span>Reinitializing...</span>
              </>
            ) : (
              <>
                <ScanIcon className="size-4 mr-2" />
                <span>Reinitialize Scan</span>
              </>
            )}
          </Button>
        </div>
      )}
    </ScrollArea>
  );
}

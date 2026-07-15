"use client";

import { Dispatch, SetStateAction } from "react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FolderGit2, FileArchive, Github, GitBranch, GitCommit } from "lucide-react";

export type RepositoryMode = "github" | "gitlab" | "bitbucket" | "unknown";

export interface RepositoryCardProps {
  /** Uploaded zip file when user chooses zip source */
  uploadedFile: File | null;
  setUploadedFile: Dispatch<SetStateAction<File | null>>;
  /** Repository URL when using repo source */
  repoUrl: string;
  setRepoUrl: Dispatch<SetStateAction<string>>;
  /** Personal Access Token for repo */
  pat: string;
  setPat: Dispatch<SetStateAction<string>>;
  /** Branch to scan (e.g. main, develop). Defaults to main in worker. */
  branch: string;
  setBranch: Dispatch<SetStateAction<string>>;
  /** Selected repo platform when using repo source */
  mode: RepositoryMode;
  setMode: Dispatch<SetStateAction<RepositoryMode>>;
}

export function RepositoryCard({
  uploadedFile,
  setUploadedFile,
  repoUrl,
  setRepoUrl,
  pat,
  setPat,
  branch,
  setBranch,
  mode,
  setMode,
}: RepositoryCardProps) {
  return (
    <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none">
      <CardHeader className="pb-2 px-4">
        <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
          <FolderGit2 className="h-4 w-4 text-zinc-400 shrink-0" />
          Repository
        </CardTitle>
        <CardDescription className="text-zinc-500 text-xs">
          Upload a zip of your code or connect a repository (GitHub, GitLab, Bitbucket).
        </CardDescription>
      </CardHeader>
      <CardContent className="px-4 pt-0">
        <Accordion type="single" collapsible className="w-full">
          <AccordionItem value="zip" className="border-zinc-800">
            <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
              <div className="flex items-center gap-2">
                <FileArchive className="h-4 w-4" />
                <span>Zip file</span>
              </div>
            </AccordionTrigger>
            <AccordionContent className="pt-3 space-y-2">
              <Label className="text-zinc-300 text-sm">Upload zip file <span className="text-red-500">*</span></Label>
              <Input
                type="file"
                accept=".zip"
                className="bg-zinc-800 h-fit p-2 border-zinc-700 text-white file:mr-2 file:rounded file:border-0 file:bg-blue-600 file:cursor-pointer file:px-3 file:py-1 file:text-sm file:text-white"
                onChange={(e) => setUploadedFile(e.target.files?.[0] ?? null)}
              />
              {uploadedFile && (
                <p className="text-xs text-zinc-500">{uploadedFile.name}</p>
              )}
            </AccordionContent>
          </AccordionItem>
          <AccordionItem value="repo" className="border-zinc-800">
            <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
              <div className="flex items-center gap-2">
                <FolderGit2 className="h-4 w-4" />
                <span>Connect to a repository</span>
              </div>
            </AccordionTrigger>
            <AccordionContent className="pt-2">
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="github" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
                    <div className="flex items-center gap-2">
                      <Github className="h-4 w-4" />
                      <span>GitHub</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="pt-3 space-y-3">
                    <Input
                      value={repoUrl}
                      placeholder="Repository URL"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => { setRepoUrl(e.target.value); setMode("github"); }}
                    />
                    <Input
                      value={branch}
                      placeholder="Branch name (leave empty for main)"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => setBranch(e.target.value)}
                    />
                    <Input
                      type="password"
                      value={pat}
                      placeholder="Personal Access Token"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => setPat(e.target.value)}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="gitlab" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
                    <div className="flex items-center gap-2">
                      <GitBranch className="h-4 w-4" />
                      <span>GitLab</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="pt-3 space-y-3">
                    <Input
                      value={repoUrl}
                      placeholder="Repository URL"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => { setRepoUrl(e.target.value); setMode("gitlab"); }}
                    />
                    <Input
                      value={branch}
                      placeholder="Branch name (leave empty for main)"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => setBranch(e.target.value)}
                    />
                    <Input
                      type="password"
                      value={pat}
                      placeholder="Personal Access Token"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => setPat(e.target.value)}
                    />
                  </AccordionContent>
                </AccordionItem>
                <AccordionItem value="bitbucket" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
                    <div className="flex items-center gap-2">
                      <GitCommit className="h-4 w-4" />
                      <span>Bitbucket</span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="pt-3 space-y-3">
                    <Input
                      value={repoUrl}
                      placeholder="Repository URL"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => { setRepoUrl(e.target.value); setMode("bitbucket"); }}
                    />
                    <Input
                      value={branch}
                      placeholder="Branch name (leave empty for main)"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => setBranch(e.target.value)}
                    />
                    <Input
                      type="password"
                      value={pat}
                      placeholder="Personal Access Token"
                      className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm"
                      onChange={(e) => setPat(e.target.value)}
                    />
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
}

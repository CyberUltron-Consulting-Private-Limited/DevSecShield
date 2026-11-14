"use client";

import { Dispatch, SetStateAction, useId, type ReactNode } from "react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
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

const inputClass = "bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 text-sm";
const labelClass = "text-zinc-300 text-xs";

/** URL, branch and token of one provider; each field has a visible label and its (i) tip. */
function ProviderFields({
  provider,
  icon,
  label,
  props,
}: {
  provider: Exclude<RepositoryMode, "unknown">;
  icon: ReactNode;
  label: string;
  props: RepositoryCardProps;
}) {
  const id = useId();
  const { repoUrl, setRepoUrl, branch, setBranch, pat, setPat, setMode } = props;
  return (
    <AccordionItem value={provider} className="border-zinc-800">
      <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
        <div className="flex items-center gap-2">
          {icon}
          <span>{label}</span>
        </div>
      </AccordionTrigger>
      <AccordionContent className="pt-3 space-y-3">
        <div className="space-y-1">
          <FieldLabel htmlFor={`${id}-url`} infoId="repo.url" labelClassName={labelClass}>Repository URL</FieldLabel>
          <Input
            id={`${id}-url`}
            value={repoUrl}
            placeholder="Repository URL"
            className={inputClass}
            onChange={(e) => { setRepoUrl(e.target.value); setMode(provider); }}
          />
        </div>
        <div className="space-y-1">
          <FieldLabel htmlFor={`${id}-branch`} infoId="repo.branch" labelClassName={labelClass}>Branch</FieldLabel>
          <Input
            id={`${id}-branch`}
            value={branch}
            placeholder="Branch name (leave empty for main)"
            className={inputClass}
            onChange={(e) => setBranch(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <FieldLabel
            htmlFor={`${id}-token`}
            infoId={provider === "github" ? "repo.pat.github" : "repo.pat.required"}
            labelClassName={labelClass}
          >
            {provider === "github" ? "Access token (optional for public repos)" : "Access token"}
          </FieldLabel>
          <Input
            id={`${id}-token`}
            type="password"
            value={pat}
            placeholder={provider === "github" ? "PAT (optional for public repos)" : "Personal Access Token"}
            className={inputClass}
            onChange={(e) => setPat(e.target.value)}
          />
        </div>
      </AccordionContent>
    </AccordionItem>
  );
}

export function RepositoryCard(props: RepositoryCardProps) {
  const { uploadedFile, setUploadedFile } = props;
  const zipId = useId();
  return (
    <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none">
      <CardHeader className="pb-2 px-4">
        <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
          <FolderGit2 className="h-4 w-4 text-zinc-400 shrink-0" />
          Repository
          <InfoTip id="repo.source" />
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
              <FieldLabel htmlFor={zipId} infoId="repo.zip" labelClassName="text-zinc-300 text-sm" required>
                Upload zip file
              </FieldLabel>
              <Input
                id={zipId}
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
                <ProviderFields provider="github" icon={<Github className="h-4 w-4" />} label="GitHub" props={props} />
                <ProviderFields provider="gitlab" icon={<GitBranch className="h-4 w-4" />} label="GitLab" props={props} />
                <ProviderFields provider="bitbucket" icon={<GitCommit className="h-4 w-4" />} label="Bitbucket" props={props} />
              </Accordion>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
}

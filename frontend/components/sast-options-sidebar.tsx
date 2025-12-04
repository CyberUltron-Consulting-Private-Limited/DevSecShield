"use client";

import { useState } from "react";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Upload,
  Link2 as LinkIcon,
  Circle,
  Github,
  GitBranch,
  Cloud,
  GitCommit,
  Server,
  Workflow,
} from "lucide-react";

const cicdPlatforms = [
  { name: "Circle CI", icon: Circle },
  { name: "Buddy", icon: Server },
  { name: "Codeship", icon: Workflow },
  { name: "GitHub", icon: Github },
  { name: "Bamboo", icon: Server },
  { name: "GitLab", icon: GitBranch },
  { name: "AWS", icon: Cloud },
  { name: "Bitbucket", icon: GitCommit },
  { name: "Travis", icon: Server },
  { name: "Jenkins", icon: Server },
];

const languages = [
  "c",
  "java",
  "php",
  "ruby",
  "rust",
  "swift",
  "python",
  "csharp",
  "kotlin",
  "javascript",
];

export function SASTOptionsSidebar() {
  const [selectedLanguage, setSelectedLanguage] = useState<string>("");
  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">SAST Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your scanning options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      <div className="p-6">
        {/* Quick Actions */}
        <div className="mb-8">
          <h3 className="text-sm font-semibold text-zinc-300 mb-4">Quick Actions</h3>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="primary-language" className="text-zinc-300">
                Application Primary Language
              </Label>
              <Select value={selectedLanguage} onValueChange={setSelectedLanguage}>
                <SelectTrigger
                  id="primary-language"
                  className="bg-zinc-800 border-zinc-700 text-white"
                >
                  <SelectValue className="text-white placeholder:text-zinc-400" placeholder="Select language" />
                </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700">
                  {languages.map((language) => (
                    <SelectItem
                      key={language}
                      value={language}
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      {language.charAt(0).toUpperCase() + language.slice(1)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        <Separator className="mb-6 bg-zinc-800" />

        {/* Integration Inputs */}
        <div className="mb-8">
          <h3 className="text-sm font-semibold text-zinc-300 mb-4 flex flex-row items-center gap-2">
            Repository Selection <p className="text-red-500">*</p>
          </h3>
          <Accordion type="single" collapsible className="w-full">
            {/* GitHub Integration */}
            <AccordionItem value="github" className="border-zinc-800">
              <AccordionTrigger className="text-zinc-300 hover:text-white">
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
                  />
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* GitLab Integration */}
            <AccordionItem value="gitlab" className="border-zinc-800">
              <AccordionTrigger className="text-zinc-300 hover:text-white">
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
                  />
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Bitbucket Integration */}
            <AccordionItem value="bitbucket" className="border-zinc-800">
              <AccordionTrigger className="text-zinc-300 hover:text-white">
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
                  />
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </div>
      </div>
    </ScrollArea>
  );
}


"use client";

import { useState } from "react";
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
  Github,
  GitBranch,
} from "lucide-react";

const packageManagers = [
  "npm",
  "yarn",
  "pnpm",
  "pip",
  "poetry",
  "maven",
  "gradle",
  "nuget",
  "composer",
  "cargo",
];

export function SCASBOMOptionsSidebar() {
  const [packageManager, setPackageManager] = useState<string>("");
  
  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">SCA + SBOM Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your SCA + SBOM scanning options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      <div className="p-6">
          {/* Quick Actions */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4">Quick Actions</h3>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="package-manager" className="text-zinc-300">
                  Package Manager
                </Label>
                <Select value={packageManager} onValueChange={setPackageManager}>
                  <SelectTrigger
                    id="package-manager"
                    className="bg-zinc-800 border-zinc-700 text-white"
                  >
                    <SelectValue className="text-white placeholder:text-zinc-400" placeholder="Select package manager" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    {packageManagers.map((pm) => (
                      <SelectItem
                        key={pm}
                        value={pm}
                        className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                      >
                        {pm.charAt(0).toUpperCase() + pm.slice(1)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <Separator className="mb-6 bg-zinc-800" />

          {/* Repository Integration */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4 flex flex-row items-center gap-2">
              Repository Integration <p className="text-red-500">*</p>
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
        </Accordion>
      </div>
      </div>
    </ScrollArea>
  );
}


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

export function DASTOptionsSidebar() {
  const [scanType, setScanType] = useState<string>("");
  
  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">DAST Options</h2>
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
                <Label htmlFor="scan-type" className="text-zinc-300">
                  Scan Type
                </Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger
                    id="scan-type"
                    className="bg-zinc-800 border-zinc-700 text-white"
                  >
                    <SelectValue className="text-white placeholder:text-zinc-400" placeholder="Select scan type" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    <SelectItem
                      value="full"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Full Scan
                    </SelectItem>
                    <SelectItem
                      value="quick"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Quick Scan
                    </SelectItem>
                    <SelectItem
                      value="crawl"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Crawl Only
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <Separator className="mb-6 bg-zinc-800" />

          {/* Target Configuration */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4 flex flex-row items-center gap-2">
              Target Configuration <p className="text-red-500">*</p>
            </h3>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target-url" className="text-zinc-300">
                  Target URL
                </Label>
                <Input
                  id="target-url"
                  placeholder="https://example.com"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="auth-token" className="text-zinc-300">
                  Authentication Token (Optional)
                </Label>
                <Input
                  id="auth-token"
                  type="password"
                  placeholder="Enter authentication token"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </ScrollArea>
  );
}


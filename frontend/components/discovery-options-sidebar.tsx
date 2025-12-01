"use client";

import { useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function DiscoveryOptionsSidebar() {
  const [discoveryType, setDiscoveryType] = useState<string>("");
  
  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">Discovery Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your discovery scanning options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      <div className="p-6">
          {/* Quick Actions */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4">Quick Actions</h3>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="discovery-type" className="text-zinc-300">
                  Discovery Type
                </Label>
                <Select value={discoveryType} onValueChange={setDiscoveryType}>
                  <SelectTrigger
                    id="discovery-type"
                    className="bg-zinc-800 border-zinc-700 text-white"
                  >
                    <SelectValue className="text-white placeholder:text-zinc-400" placeholder="Select discovery type" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    <SelectItem
                      value="network"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Network Discovery
                    </SelectItem>
                    <SelectItem
                      value="service"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Service Discovery
                    </SelectItem>
                    <SelectItem
                      value="asset"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Asset Discovery
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          <Separator className="mb-6 bg-zinc-800" />

          {/* Configuration */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4 flex flex-row items-center gap-2">
              Configuration <p className="text-red-500">*</p>
            </h3>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target-range" className="text-zinc-300">
                  Target Range / Domain
                </Label>
                <Input
                  id="target-range"
                  placeholder="192.168.1.0/24 or example.com"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="scan-depth" className="text-zinc-300">
                  Scan Depth
                </Label>
                <Select>
                  <SelectTrigger
                    id="scan-depth"
                    className="bg-zinc-800 border-zinc-700 text-white"
                  >
                    <SelectValue className="text-white placeholder:text-zinc-400" placeholder="Select depth" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    <SelectItem
                      value="shallow"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Shallow
                    </SelectItem>
                    <SelectItem
                      value="medium"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Medium
                    </SelectItem>
                    <SelectItem
                      value="deep"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Deep
                    </SelectItem>
                  </SelectContent>
                </Select>
          </div>
        </div>
      </div>
      </div>
    </ScrollArea>
  );
}


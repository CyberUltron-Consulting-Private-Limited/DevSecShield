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

export function LLMOptionsSidebar() {
  const [model, setModel] = useState<string>("");
  
  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">LLM Benchmark Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your LLM benchmark scanning options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      <div className="p-6">
          {/* Quick Actions */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4">Quick Actions</h3>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="llm-model" className="text-zinc-300">
                  LLM Model
                </Label>
                <Select value={model} onValueChange={setModel}>
                  <SelectTrigger
                    id="llm-model"
                    className="bg-zinc-800 border-zinc-700 text-white"
                  >
                    <SelectValue className="text-white placeholder:text-zinc-400" placeholder="Select model" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    <SelectItem
                      value="gpt-4"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      GPT-4
                    </SelectItem>
                    <SelectItem
                      value="gpt-3.5"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      GPT-3.5
                    </SelectItem>
                    <SelectItem
                      value="claude"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Claude
                    </SelectItem>
                    <SelectItem
                      value="llama"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Llama
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
              Benchmark Configuration <p className="text-red-500">*</p>
            </h3>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="benchmark-suite" className="text-zinc-300">
                  Benchmark Suite
                </Label>
                <Input
                  id="benchmark-suite"
                  placeholder="Select benchmark suite"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="api-key" className="text-zinc-300">
                  API Key (Optional)
                </Label>
                <Input
                  id="api-key"
                  type="password"
                  placeholder="Enter API key"
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


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

export function MCPOptionsSidebar() {
  const [mcpType, setMcpType] = useState<string>("");
  
  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">MCP Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your MCP scanning options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      <div className="p-6">
          {/* Quick Actions */}
          <div className="mb-8">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4">Quick Actions</h3>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="mcp-type" className="text-zinc-300">
                  MCP Type
                </Label>
                <Select value={mcpType} onValueChange={setMcpType}>
                  <SelectTrigger
                    id="mcp-type"
                    className="bg-zinc-800 border-zinc-700 text-white"
                  >
                    <SelectValue className="text-white placeholder:text-zinc-400" placeholder="Select MCP type" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    <SelectItem
                      value="server"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Server
                    </SelectItem>
                    <SelectItem
                      value="client"
                      className="text-white hover:bg-zinc-700 focus:bg-zinc-700"
                    >
                      Client
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
                <Label htmlFor="mcp-endpoint" className="text-zinc-300">
                  MCP Endpoint
                </Label>
                <Input
                  id="mcp-endpoint"
                  placeholder="https://mcp.example.com"
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


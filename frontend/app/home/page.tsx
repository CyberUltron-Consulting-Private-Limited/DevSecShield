"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function HomePage() {
  return (
    <div className="flex items-center justify-center h-full bg-white dark:bg-zinc-900">
      <div className="text-center space-y-4">
        <h1 className="text-2xl font-bold text-zinc-900 dark:text-white">
          Welcome to DevSec Shield
        </h1>
        <p className="text-zinc-600 dark:text-zinc-400">
          Select a scan type from the sidebar to get started.
        </p>
        <div className="flex flex-col gap-2">
        <Link href="/home/sast/new">
            <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
              Start a SAST Scan
            </Button>
          </Link>
          <Link href="/home/sca_sbom/new">
            <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
              Start a SCA + SBOM Scan
            </Button>
          </Link>
          <Link href="/home/dast/new">
            <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
              Start a DAST Scan
            </Button>
          </Link>
          <Link href="/home/mcp/new">
            <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
              Start a MCP Scan
            </Button>
          </Link>
          <Link href="/home/llm/new">
            <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
              Start a LLM Benchmark Scan
            </Button>
          </Link>
          <Link href="/home/iac/new">
            <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
              Start an IAC Scan
            </Button>
          </Link>
          <Link href="/home/discovery/new">
            <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
              Start a Discovery Scan
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}


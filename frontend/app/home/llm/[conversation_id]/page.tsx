"use client";

import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Triangle,
  Calendar,
  Shield,
  TrendingUp,
  Search,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { LLMOptionsSidebar } from "@/components/llm-options-sidebar";

const dashboardCards = [
  {
    title: "List down 10 vulnerabilities",
    description: "Displays top 10 discovered vulnerabilities.",
    icon: Triangle,
    iconColor: "text-blue-400",
    bgColor: "bg-blue-50 dark:bg-blue-950/20",
  },
  {
    title: "List down last month vulnerabilities",
    description: "Shows vulnerabilities from last month's scan.",
    icon: Calendar,
    iconColor: "text-green-400",
    bgColor: "bg-green-50 dark:bg-green-950/20",
  },
  {
    title: "List down 10 critical vulnerabilities",
    description: "Filters and displays 10 most severe vulnerabilities.",
    icon: Shield,
    iconColor: "text-blue-400",
    bgColor: "bg-blue-50 dark:bg-blue-950/20",
  },
  {
    title: "List down 10 medium vulnerabilities",
    description: "Filters and displays 10 medium-severity vulnerabilities.",
    icon: TrendingUp,
    iconColor: "text-green-400",
    bgColor: "bg-green-50 dark:bg-green-950/20",
  },
];

interface LLMPageProps {
  params: {
    conversation_id: string;
  };
}

export default function LLMPage({ params }: LLMPageProps) {
  return (
    <div className="flex h-full">
      {/* Main Content Area */}
      <div className="flex-1 bg-white dark:bg-zinc-900 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
              LLM Benchmark Scanning
            </h1>
            <p className="text-zinc-600 dark:text-zinc-400">
              Run a comprehensive LLM benchmark scan on your application. Explore and analyze the results to identify and fix vulnerabilities.
            </p>
          </div>

          {/* Vulnerability Summary */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex flex-col items-end gap-2">
              <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer">
                Scan Now
              </Button>
            </div>
          </div>

          {/* Dashboard Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            {dashboardCards.map((card, index) => {
              const Icon = card.icon;
              return (
                <Card key={index} className="hover:shadow-lg transition-shadow">
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className={cn("p-3 rounded-lg", card.bgColor)}>
                        <Icon className={cn("h-6 w-6", card.iconColor)} />
                      </div>
                    </div>
                    <CardTitle className="mt-4 text-zinc-900 dark:text-white">
                      {card.title}
                    </CardTitle>
                    <CardDescription className="text-zinc-600 dark:text-zinc-400">
                      {card.description}
                    </CardDescription>
                  </CardHeader>
                </Card>
              );
            })}
          </div>

          {/* Search Bar */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-zinc-400" />
            <Input
              placeholder="Search vulnerabilities, projects, or scans..."
              className="pl-10 h-12 text-base"
            />
          </div>
        </div>
      </div>

      {/* Right Sidebar - LLM Options */}
      <LLMOptionsSidebar />
    </div>
  );
}


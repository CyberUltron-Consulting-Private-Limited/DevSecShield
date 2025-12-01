"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Plus, Calendar, Clock } from "lucide-react";
import { useEffect, useState } from "react";

interface Conversation {
  id: number;
  name: string;
  created_at: string;
  updated_at: string;
}

export default function MCPPage() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // TODO: Fetch conversations from API
    setLoading(false);
  }, []);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  return (
    <div className="flex h-full bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
                MCP Scans
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your MCP scan conversations.
              </p>
            </div>
            <Link href="/home/mcp/new">
              <Button className="bg-teal-600 hover:bg-teal-700 text-white">
                <Plus className="h-4 w-4 mr-2" />
                New Scan
              </Button>
            </Link>
          </div>

          {/* Conversations List */}
          {loading ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400">Loading...</p>
            </div>
          ) : conversations.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                No scans yet. Create your first MCP scan to get started.
              </p>
              <Link href="/home/mcp/new">
                <Button className="bg-teal-600 hover:bg-teal-700 text-white">
                  <Plus className="h-4 w-4 mr-2" />
                  Create New Scan
                </Button>
              </Link>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {conversations.map((conversation) => (
                <Link
                  key={conversation.id}
                  href={`/home/mcp/${conversation.id}`}
                >
                  <Card className="hover:shadow-lg transition-shadow cursor-pointer h-full">
                    <CardHeader>
                      <CardTitle className="text-zinc-900 dark:text-white">
                        {conversation.name || `Scan #${conversation.id}`}
                      </CardTitle>
                      <CardDescription className="flex flex-col gap-2 mt-2">
                        <div className="flex items-center gap-2 text-zinc-500 dark:text-zinc-400">
                          <Calendar className="h-4 w-4" />
                          <span>Created {formatDate(conversation.created_at)}</span>
                        </div>
                        <div className="flex items-center gap-2 text-zinc-500 dark:text-zinc-400">
                          <Clock className="h-4 w-4" />
                          <span>Updated {formatDate(conversation.updated_at)}</span>
                        </div>
                      </CardDescription>
                    </CardHeader>
                  </Card>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


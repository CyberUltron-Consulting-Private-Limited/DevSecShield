"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  Crosshair,
  Globe,
  Loader2,
  ArrowLeft,
  FileText,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import Link from "next/link";

interface CreateProjectPayload {
  name: string;
  targetDomain: string;
  description?: string;
  [key: string]: unknown;
}

function teamHeaders(teamId: string): Record<string, string> {
  return { "X-Team-Id": teamId };
}

async function fetchDefaults(teamId: string): Promise<Record<string, unknown>> {
  const res = await fetch("/api/redteam/projects/defaults", {
    headers: teamHeaders(teamId),
  });
  if (!res.ok) return {};
  return res.json();
}

async function createProject(teamId: string, payload: CreateProjectPayload) {
  const res = await fetch("/api/redteam/projects", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...teamHeaders(teamId) },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to create project");
  }
  return res.json();
}

export default function NewRedTeamProjectPage() {
  const params = useParams();
  const router = useRouter();
  const teamId = params?.team_id as string;
  const queryClient = useQueryClient();

  const [name, setName] = useState("");
  const [targetDomain, setTargetDomain] = useState("");
  const [description, setDescription] = useState("");

  const { data: defaults } = useQuery({
    queryKey: ["redamon-defaults", teamId],
    queryFn: () => fetchDefaults(teamId),
    enabled: !!teamId,
  });

  const createMutation = useMutation({
    mutationFn: (payload: CreateProjectPayload) => createProject(teamId, payload),
    onSuccess: (project) => {
      queryClient.invalidateQueries({ queryKey: ["redamon-projects"] });
      toast.success("Project created successfully");
      router.push(`/${teamId}/redteam/${project.id}`);
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !targetDomain.trim()) {
      toast.error("Name and target domain are required");
      return;
    }

    createMutation.mutate({
      ...defaults,
      name: name.trim(),
      targetDomain: targetDomain.trim(),
      description: description.trim() || undefined,
    });
  };

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-950">
      <div className="mx-auto max-w-2xl px-6 py-8">
        {/* Back link */}
        <Link
          href={`/${teamId}/redteam`}
          className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white mb-6 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Projects
        </Link>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center h-10 w-10 rounded-lg bg-red-600/10">
                <Crosshair className="h-5 w-5 text-red-500" />
              </div>
              <div>
                <CardTitle className="text-xl">New Red Team Project</CardTitle>
                <CardDescription>
                  Configure the target for autonomous reconnaissance and exploitation.
                  Advanced settings can be adjusted after creation.
                </CardDescription>
              </div>
            </div>
          </CardHeader>

          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="name" className="text-sm font-medium">
                  Project Name <span className="text-red-500">*</span>
                </Label>
                <Input
                  id="name"
                  placeholder="e.g. Company X Pentest"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="domain" className="text-sm font-medium">
                  Target Domain <span className="text-red-500">*</span>
                </Label>
                <div className="relative">
                  <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                  <Input
                    id="domain"
                    className="pl-9"
                    placeholder="e.g. example.com"
                    value={targetDomain}
                    onChange={(e) => setTargetDomain(e.target.value)}
                    required
                  />
                </div>
                <p className="text-xs text-zinc-500">
                  The primary domain to target. Subdomain discovery will find additional assets.
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="description" className="text-sm font-medium">
                  Description
                </Label>
                <div className="relative">
                  <Textarea
                    id="description"
                    placeholder="Optional notes about scope, objectives, or constraints..."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={3}
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => router.push(`/${teamId}/redteam`)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={createMutation.isPending || !name.trim() || !targetDomain.trim()}
                  className="gap-1.5 bg-red-600 hover:bg-red-700 text-white"
                >
                  {createMutation.isPending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    "Create Project"
                  )}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

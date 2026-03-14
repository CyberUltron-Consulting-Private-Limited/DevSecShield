"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  Plus,
  Crosshair,
  Globe,
  Trash2,
  Loader2,
  RefreshCcw,
  ExternalLink,
  MoreVertical,
  Settings,
  FolderOpen,
  Calendar,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";

interface RedamonProject {
  id: string;
  name: string;
  targetDomain: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

function teamHeaders(teamId: string): HeadersInit {
  return { "X-Team-Id": teamId };
}

async function fetchRedamonProjects(teamId: string): Promise<RedamonProject[]> {
  const res = await fetch("/api/redteam/projects", {
    headers: teamHeaders(teamId),
  });
  if (!res.ok) throw new Error("Failed to fetch projects");
  return res.json();
}

async function deleteRedamonProject(teamId: string, projectId: string): Promise<void> {
  const res = await fetch(`/api/redteam/projects/${projectId}`, {
    method: "DELETE",
    headers: teamHeaders(teamId),
  });
  if (!res.ok) throw new Error("Failed to delete project");
}

export default function RedTeamPage() {
  const params = useParams();
  const router = useRouter();
  const teamId = params?.team_id as string;
  const queryClient = useQueryClient();
  const [deleteTarget, setDeleteTarget] = useState<RedamonProject | null>(null);

  const {
    data: projects,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ["redamon-projects", teamId],
    queryFn: () => fetchRedamonProjects(teamId),
    enabled: !!teamId,
  });

  const deleteMutation = useMutation({
    mutationFn: (projectId: string) => deleteRedamonProject(teamId, projectId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["redamon-projects"] });
      toast.success("Project deleted");
      setDeleteTarget(null);
    },
    onError: () => toast.error("Failed to delete project"),
  });

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-950">
      <div className="mx-auto max-w-6xl px-6 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center h-10 w-10 rounded-lg bg-red-600/10">
              <Crosshair className="h-5 w-5 text-red-500" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-zinc-900 dark:text-white">
                Red Team Operations
              </h1>
              <p className="text-sm text-zinc-500 dark:text-zinc-400">
                Autonomous reconnaissance, exploitation, and remediation
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isLoading}
              className="gap-1.5"
            >
              <RefreshCcw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button
              size="sm"
              className="gap-1.5 bg-red-600 hover:bg-red-700 text-white"
              onClick={() => router.push(`/${teamId}/redteam/new`)}
              disabled={!teamId}
            >
              <Plus className="h-3.5 w-3.5" />
              New Project
            </Button>
          </div>
        </div>

        {/* Content */}
        {isLoading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2 className="h-8 w-8 animate-spin text-red-500" />
          </div>
        ) : projects && projects.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {projects.map((project) => (
              <Card
                key={project.id}
                className="group border-zinc-200 dark:border-zinc-800 hover:border-red-500/40 dark:hover:border-red-500/40 transition-colors cursor-pointer"
                onClick={() =>
                  router.push(`/${teamId}/redteam/${project.id}`)
                }
              >
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <CardTitle className="text-base font-semibold text-zinc-900 dark:text-white truncate">
                        {project.name}
                      </CardTitle>
                      <CardDescription className="flex items-center gap-1.5 mt-1">
                        <Globe className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate">{project.targetDomain}</span>
                      </CardDescription>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          onClick={(e) => {
                            e.stopPropagation();
                            router.push(`/${teamId}/redteam/${project.id}`);
                          }}
                        >
                          <ExternalLink className="h-4 w-4 mr-2" />
                          Open
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={(e) => {
                            e.stopPropagation();
                            router.push(`/${teamId}/redteam/${project.id}/settings`);
                          }}
                        >
                          <Settings className="h-4 w-4 mr-2" />
                          Settings
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-red-600 focus:text-red-600"
                          onClick={(e) => {
                            e.stopPropagation();
                            setDeleteTarget(project);
                          }}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>
                <CardContent>
                  {project.description && (
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-3 line-clamp-2">
                      {project.description}
                    </p>
                  )}
                  <div className="flex items-center gap-2 text-xs text-zinc-400">
                    <Calendar className="h-3 w-3" />
                    <span>{formatDate(project.createdAt)}</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <div className="flex items-center justify-center h-16 w-16 rounded-full bg-zinc-100 dark:bg-zinc-800 mb-4">
              <FolderOpen className="h-8 w-8 text-zinc-400" />
            </div>
            <h2 className="text-lg font-semibold text-zinc-900 dark:text-white mb-1">
              No Projects Yet
            </h2>
            <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6 max-w-sm">
              Create your first red team project to start autonomous reconnaissance and exploitation.
            </p>
            <Button
              className="gap-1.5 bg-red-600 hover:bg-red-700 text-white"
              onClick={() => router.push(`/${teamId}/redteam/new`)}
              disabled={!teamId}
            >
              <Plus className="h-4 w-4" />
              Create Project
            </Button>
          </div>
        )}
      </div>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={() => setDeleteTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Project</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete{" "}
              <span className="font-semibold text-zinc-900 dark:text-white">
                {deleteTarget?.name}
              </span>
              ? This will remove all scan data, graph nodes, and conversations. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
              ) : (
                <Trash2 className="h-4 w-4 mr-1.5" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

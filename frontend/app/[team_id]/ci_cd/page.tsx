"use client";

import Link from "next/link";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Plus, RefreshCcw, Loader2, MoreVertical, Pencil, Trash2, Copy, Check } from "lucide-react";
import { useEffect, useState } from "react";
import { CicdIntegration, getCicdIntegrations, createCicdIntegration, CreateCicdIntegrationData, deleteCicdIntegration, renameCicdIntegration } from "@/utils/backend_api";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { showErrorToast } from "@/utils/error-handler";
import { toast } from "sonner";
import { useRouter, useParams } from "next/navigation";

export default function CicdPage() {
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const queryClient = useQueryClient();
  const [integrations, setIntegrations] = useState<CicdIntegration[]>([]);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState<CicdIntegration | null>(null);
  const [newName, setNewName] = useState("");
  const [copiedKeyId, setCopiedKeyId] = useState<number | null>(null);
  const [formTitle, setFormTitle] = useState("");
  const [formScanType, setFormScanType] = useState<"sast" | "">("");
  const router = useRouter();
  const query = useQuery({ 
    queryKey: ['cicd-integrations', team_id], 
    queryFn: () => getCicdIntegrations(Number(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data) {
      setIntegrations(query.data);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching CI/CD integrations');
    }
  }, [query.data, query.error]);

  const createCicdIntegrationMutation = useMutation({
    mutationFn: (data: CreateCicdIntegrationData) => createCicdIntegration(Number(team_id), data),
    onSuccess: (data: { integration_id: number }) => {
      queryClient.invalidateQueries({ queryKey: ['cicd-integrations', team_id] });
      setCreateDialogOpen(false);
      setFormTitle("");
      setFormScanType("");
      toast.success('CI/CD integration created successfully');
      router.push(`/${team_id}/ci_cd/${data.integration_id}`);
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const deleteCicdIntegrationMutation = useMutation({
    mutationFn: (integration_id: number) => deleteCicdIntegration(Number(team_id), integration_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cicd-integrations', team_id] });
      toast.success('CI/CD integration deleted successfully');
      setDeleteDialogOpen(false);
      setSelectedIntegration(null);
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameCicdIntegrationMutation = useMutation({
    mutationFn: ({ integration_id, title }: { integration_id: number; title: string }) =>
      renameCicdIntegration({ team_id: Number(team_id), integration_id, title }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cicd-integrations', team_id] });
      toast.success('CI/CD integration renamed successfully');
      setRenameDialogOpen(false);
      setSelectedIntegration(null);
      setNewName("");
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const handleRename = (integration: CicdIntegration) => {
    setSelectedIntegration(integration);
    setNewName(integration.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (integration: CicdIntegration) => {
    setSelectedIntegration(integration);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedIntegration && newName.trim()) {
      renameCicdIntegrationMutation.mutate({ integration_id: selectedIntegration.id, title: newName.trim() });
    }
  };

  const confirmDelete = () => {
    if (selectedIntegration) {
      deleteCicdIntegrationMutation.mutate(selectedIntegration.id);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };


  const redactApiKey = (apiKey: string) => {
    if (apiKey.length <= 8) {
      return "•".repeat(apiKey.length);
    }
    // Show first 4 and last 4 characters, redact the middle
    const start = apiKey.substring(0, 4);
    const end = apiKey.substring(apiKey.length - 4);
    return `${start}${"*******"}${end}`;
  };

  const copyApiKey = async (apiKey: string, integrationId: number) => {
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopiedKeyId(integrationId);
      toast.success("API key copied to clipboard");
      setTimeout(() => {
        setCopiedKeyId(null);
      }, 2000);
    } catch (error) {
      toast.error("Failed to copy API key");
    }
  };

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
                CI/CD Integrations
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your CI/CD integrations.
              </p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button 
                className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
                onClick={() => queryClient.invalidateQueries({ queryKey: ['cicd-integrations'] })}
              >
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <Button 
                className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Integration
              </Button>
            </div>
          </div>

          {/* Integrations Table */}
          {query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                Error in fetching integrations, please try again later
              </p>
            </div>
          ) : query.isLoading ? (
            <div className="flex h-full items-center justify-center">
              <Loader2 className="size-10 animate-spin text-teal-600" />
            </div>
          ) : integrations.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                No integrations yet. Create your first CI/CD integration to get started.
              </p>
              <Button 
                className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                Create Integration
              </Button>
            </div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[300px]">Title</TableHead>
                    <TableHead>Scan Type</TableHead>
                    <TableHead>Created At</TableHead>
                    <TableHead>Last Updated</TableHead>
                    <TableHead>API Key</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {integrations.map((integration) => (
                    <TableRow key={integration.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                      <TableCell className="font-medium">
                        <Link
                          href={`/${team_id}/ci_cd/${integration.id}`}
                          className="text-teal-600 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300 hover:underline cursor-pointer"
                        >
                          {integration.title}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {integration.scan_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(integration.created_at)}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(integration.last_updated)}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <code className="text-sm bg-zinc-100 dark:bg-zinc-800 px-2 py-1 rounded font-mono">
                            {redactApiKey(integration.api_key)}
                          </code>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 cursor-pointer"
                            onClick={() => copyApiKey(integration.api_key, integration.id)}
                            title="Copy API key"
                          >
                            {copiedKeyId === integration.id ? (
                              <Check className="h-4 w-4 text-green-600" />
                            ) : (
                              <Copy className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8 cursor-pointer"
                            >
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              className="cursor-pointer"
                              onClick={() => handleRename(integration)}
                            >
                              <Pencil className="h-4 w-4 mr-2" />
                              Rename
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="cursor-pointer"
                              onClick={() => handleDelete(integration)}
                              variant="destructive"
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      </div>

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create CI/CD Integration</DialogTitle>
            <DialogDescription>
              Enter the details for your new CI/CD integration.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4 space-y-4">
            <div className="space-y-2">
              <Label htmlFor="title" className="cursor-pointer">Title *</Label>
              <Input
                id="title"
                value={formTitle}
                onChange={(e) => setFormTitle(e.target.value)}
                placeholder="Integration name"
                required
                onKeyDown={(e) => {
                  if (e.key === "Enter" && formTitle.trim() && formScanType) {
                    createCicdIntegrationMutation.mutate({
                      title: formTitle.trim(),
                      scan_type: formScanType as "sast",
                    });
                  }
                }}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="scan_type" className="cursor-pointer">Scan Type *</Label>
              <Select
                value={formScanType}
                onValueChange={(value) => setFormScanType(value as "sast")}
              >
                <SelectTrigger id="scan_type">
                  <SelectValue placeholder="Select scan type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sast">SAST</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setFormTitle("");
                setFormScanType("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!formTitle.trim()) {
                  toast.error("Title is required");
                  return;
                }
                if (!formScanType) {
                  toast.error("Scan type is required");
                  return;
                }
                
                createCicdIntegrationMutation.mutate({
                  title: formTitle.trim(),
                  scan_type: formScanType as "sast",
                });
              }}
              disabled={!formTitle.trim() || !formScanType || createCicdIntegrationMutation.isPending}
              className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
            >
              {createCicdIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rename Dialog */}
      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Integration</DialogTitle>
            <DialogDescription>
              Enter a new name for this integration.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Integration name"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  confirmRename();
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setRenameDialogOpen(false);
                setNewName("");
                setSelectedIntegration(null);
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmRename}
              disabled={!newName.trim() || renameCicdIntegrationMutation.isPending}
              className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
            >
              {renameCicdIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Integration</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete "{selectedIntegration?.title}"? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setDeleteDialogOpen(false);
                setSelectedIntegration(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              className="cursor-pointer"
              onClick={confirmDelete}
              disabled={deleteCicdIntegrationMutation.isPending}
            >
              {deleteCicdIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


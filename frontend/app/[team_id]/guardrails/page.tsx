"use client";

import Link from "next/link";
import { useRouter, useParams } from "next/navigation";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Copy, Check, X } from "lucide-react";
import { useEffect, useState } from "react";
import { GuardrailsIntegration, deleteGuardrailsIntegration, getGuardrailsIntegrations, renameGuardrailsIntegration, createGuardrailsIntegration, SettingsData } from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

const defaultLanguages = ["ARM Assembly", "AppleScript", "C", "C#", "C++", "COBOL", "Erlang", "Fortran", "Go", "Java", "JavaScript", "Kotlin", "Lua", "Mathematica/Wolfram Language", "PHP", "Pascal", "Perl", "PowerShell", "Python", "R", "Ruby", "Rust", "Scala", "Swift", "Visual Basic .NET", "jq"];

export default function GuardrailsPage() {
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const router = useRouter();
  const [integrations, setIntegrations] = useState<GuardrailsIntegration[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedIntegration, setSelectedIntegration] = useState<GuardrailsIntegration | null>(null);
  const [newName, setNewName] = useState("");
  const [copiedKeyId, setCopiedKeyId] = useState<number | null>(null);
  
  // Form state
  const [formTitle, setFormTitle] = useState("");
  const [formSettings, setFormSettings] = useState<SettingsData>({
    anonymize_context: { preamble: "", threshold: 0.1, allowed_names: [] },
    toxicity_context: { threshold: 0.1 },
    tokenlimit_context: { max_tokens: 2000 },
    promptinjection_context: { threshold: 0.1 },
    regex_context: { regex_patterns: [], redact: false },
    code_context: { languages: defaultLanguages, is_blocked: true },
    secrets_context: { redact_mode: "REDACT_PARTIAL" },
  });
  
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['guardrails-integrations', team_id],
    queryFn: () => getGuardrailsIntegrations(Number(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data) {
      setIntegrations(query.data);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching guardrails integrations');
    }
  }, [query.data, query.error]);

  const deleteGuardrailsIntegrationMutation = useMutation({
    mutationFn: (integration_id: number) => deleteGuardrailsIntegration(Number(team_id), integration_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] });
      toast.success('Guardrails integration deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameGuardrailsIntegrationMutation = useMutation({
    mutationFn: ({ integration_id, title }: { integration_id: number; title: string }) =>
      renameGuardrailsIntegration({ team_id: Number(team_id), integration_id, title }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] });
      toast.success('Guardrails integration renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const createGuardrailsIntegrationMutation = useMutation({
    mutationFn: (data: { title: string }) => createGuardrailsIntegration(Number(team_id), data),
    onSuccess: (data: { integration_id: number }) => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] });
      setCreateDialogOpen(false);
      setFormTitle("");
      setFormSettings({
        anonymize_context: { preamble: "", threshold: 0.1, allowed_names: [] },
        toxicity_context: { threshold: 0.1 },
        tokenlimit_context: { max_tokens: 2000 },
        promptinjection_context: { threshold: 0.1 },
        regex_context: { regex_patterns: [], redact: false },
        code_context: { languages: defaultLanguages, is_blocked: true },
        secrets_context: { redact_mode: "REDACT_PARTIAL" },
      });
      router.push(`/${team_id}/guardrails/${data.integration_id}`);
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

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

  const handleRename = (integration: GuardrailsIntegration) => {
    setSelectedIntegration(integration);
    setNewName(integration.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (integration: GuardrailsIntegration) => {
    setSelectedIntegration(integration);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedIntegration && newName.trim()) {
      renameGuardrailsIntegrationMutation.mutate({ integration_id: selectedIntegration.id, title: newName.trim() });
    }
  };

  const confirmDelete = () => {
    if (selectedIntegration) {
      deleteGuardrailsIntegrationMutation.mutate(selectedIntegration.id);
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
                Guardrails Integrations
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your active guardrails integrations.
              </p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => queryClient.invalidateQueries({ queryKey: ['guardrails-integrations', team_id] })}
              >
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
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
              <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : integrations.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                No integrations yet. Create your first guardrails integration to get started.
              </p>
            </div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[300px]">Title</TableHead>
                    <TableHead>Owner</TableHead>
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
                          href={`/${team_id}/guardrails/${integration.id}`}
                          className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer"
                        >
                          {integration.title}
                        </Link>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {integration.owner_user_full_name != null && integration.owner_user_full_name !== "" || integration.owner_user_email ? (
                          <div className="flex items-center gap-2">
                            <Avatar className="h-8 w-8 shrink-0">
                              <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">
                                {integration.owner_user_full_name
                                  ? integration.owner_user_full_name
                                      .trim()
                                      .split(/\s+/)
                                      .map((p) => p.charAt(0))
                                      .slice(0, 2)
                                      .join("")
                                      .toUpperCase() || (integration.owner_user_email?.[0] ?? "?").toUpperCase()
                                  : (integration.owner_user_email?.[0] ?? "?").toUpperCase()}
                              </AvatarFallback>
                            </Avatar>
                            <div className="min-w-0">
                              {integration.owner_user_full_name != null && integration.owner_user_full_name !== "" && (
                                <span className="block truncate max-w-[160px]" title={integration.owner_user_email ?? ""}>
                                  {integration.owner_user_full_name}
                                </span>
                              )}
                              {integration.owner_user_email != null && integration.owner_user_email !== "" && (
                                <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">
                                  {integration.owner_user_email}
                                </span>
                              )}
                            </div>
                          </div>
                        ) : (
                          "—"
                        )}
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
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmRename}
              disabled={!newName.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
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
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Guardrails Integration</DialogTitle>
            <DialogDescription>
              Enter a name for your guardrails integration. You can configure settings later from the integration dashboard.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4">
            <div className="space-y-2">
              <Label htmlFor="title" className="cursor-pointer">Title *</Label>
              <Input
                id="title"
                value={formTitle}
                onChange={(e) => setFormTitle(e.target.value)}
                placeholder="Integration name"
                required
                onKeyDown={(e) => {
                  if (e.key === "Enter" && formTitle.trim()) {
                    createGuardrailsIntegrationMutation.mutate({
                      title: formTitle.trim(),
                    });
                  }
                }}
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setFormTitle("");
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
                
                createGuardrailsIntegrationMutation.mutate({
                  title: formTitle.trim(),
                });
              }}
              disabled={!formTitle.trim() || createGuardrailsIntegrationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createGuardrailsIntegrationMutation.isPending && (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              )}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


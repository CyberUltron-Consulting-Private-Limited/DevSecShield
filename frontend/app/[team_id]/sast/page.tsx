"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
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
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, Play, CheckCircle, XCircle, CalendarPlus, CalendarCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { SastConversation  , deleteSastConversation, getSastConversations, renameSastConversation, createSastConversation } from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started";


export default function SASTPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string;
  const [conversations, setConversations] = useState<SastConversation[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<SastConversation | null>(null);
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false);
  const [metadataScan, setMetadataScan] = useState<SastConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  // Access the client
  const queryClient = useQueryClient()

  // Queries
  const query = useQuery({
    queryKey: ['sast-conversations', team_id],
    queryFn: () => getSastConversations(parseInt(team_id)),
    enabled: !!team_id,
  })

  useEffect(() => {
    if (query.data) {
      setConversations(query.data.scans_list_data ?? []);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching sast conversations');
    }
  }, [query.data, query.error]);

  //mutations
  const deleteSastConversationMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteSastConversation(team_id, scan_id),
    onSuccess: (data, variables, context) => {
      queryClient.invalidateQueries({ queryKey: ['sast-conversations', variables.team_id.toString()] });
      toast.success('Sast conversation deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  })

  const renameSastConversationMutation = useMutation({
    mutationFn: renameSastConversation,
    onSuccess: (data, variables, context) => {
      queryClient.invalidateQueries({ queryKey: ['sast-conversations', variables.team_id.toString()] });
      toast.success('Sast conversation renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  })

  const createSastConversationMutation = useMutation({
    mutationFn: ({ team_id, title }: { team_id: number; title: string }) => createSastConversation(team_id, title),
    onSuccess: (scan_id, variables, context) => {
      queryClient.invalidateQueries({ queryKey: ['sast-conversations', variables.team_id.toString()] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${variables.team_id}/sast/${scan_id}`);
    },
    onError: (error) => {
      showErrorToast(error);
    }
  })



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

  const getStatusBadge = (status: ScanStatus) => {
    const variants = {
      not_started: { variant: "outline" as const, className: "text-zinc-500 dark:text-zinc-500" },
      pending: { variant: "outline" as const, className: "text-zinc-600 dark:text-zinc-400" },
      started: { variant: "secondary" as const, className: "bg-blue-500 hover:bg-blue-600 text-white" },
      retry: { variant: "secondary" as const, className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      failure: { variant: "destructive" as const, className: "" },
      success: { variant: "default" as const, className: "bg-green-500 hover:bg-green-600 text-white" },
    };

    const config = variants[status];
    const labels = {
      not_started: "Not Started",
      pending: "Pending",
      started: "Started",
      retry: "Retry",
      failure: "Failure",
      success: "Success",
    };

    return (
      <Badge variant={config.variant} className={config.className}>
        {labels[status]}
      </Badge>
    );
  };

  const handleRename = (conversation: SastConversation) => {
    setSelectedConversation(conversation);
    setNewName(conversation.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (conversation: SastConversation) => {
    setSelectedConversation(conversation);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameSastConversationMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false);
      setSelectedConversation(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteSastConversationMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false);
      setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      createSastConversationMutation.mutate({ team_id: parseInt(team_id), title: newScanTitle.trim() });
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
                SAST Scans
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your SAST scan conversations.
              </p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                New Scan
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ['sast-conversations', team_id] })}>
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>

          {/* Summary cards (shown when we have card_data from the list API) */}
          {query.data?.card_data && !query.isLoading && !query.isError && (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Pending</CardTitle>
                  <Clock className="h-4 w-4 text-zinc-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-zinc-900 dark:text-white">{query.data.card_data.pending_scans}</div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">Queued</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Started</CardTitle>
                  <Play className="h-4 w-4 text-blue-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-zinc-900 dark:text-white">{query.data.card_data.started_scans}</div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">In progress</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Success</CardTitle>
                  <CheckCircle className="h-4 w-4 text-green-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-zinc-900 dark:text-white">{query.data.card_data.success_scans}</div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">Completed</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Failure</CardTitle>
                  <XCircle className="h-4 w-4 text-red-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-zinc-900 dark:text-white">{query.data.card_data.failure_scans}</div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">Failed</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Created today</CardTitle>
                  <CalendarPlus className="h-4 w-4 text-zinc-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-zinc-900 dark:text-white">{query.data.card_data.scans_created_today}</div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">New scans</p>
                </CardContent>
              </Card>
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Updated today</CardTitle>
                  <CalendarCheck className="h-4 w-4 text-zinc-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-zinc-900 dark:text-white">{query.data.card_data.scans_updated_today}</div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">Last 24h</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Conversations Table */}
          { query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                Error in fetching conversations , please try again later
              </p>
            </div>
          ) : query.isLoading ? (
            <div className="flex h-full items-center justify-center">
                <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : conversations.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                No scans yet. Create your first SAST scan to get started.
              </p>
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                Create New Scan
              </Button>
            </div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[220px]">Title</TableHead>
                    <TableHead>Owner</TableHead>
                    <TableHead>Created at</TableHead>
                    <TableHead>Last updated</TableHead>
                    <TableHead>Scan status</TableHead>
                    <TableHead className="w-[180px]">View scan metadata</TableHead>
                    <TableHead className="text-right w-[80px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {conversations.map((conversation) => (
                    <TableRow key={conversation.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                      <TableCell className="font-medium">
                        <Link
                          href={conversation.scan_status === "success" ? `/${team_id}/sast/${conversation.id}/results` : `/${team_id}/sast/${conversation.id}`}
                          className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer"
                        >
                          {conversation.title}
                        </Link>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {conversation.owner_user_full_name != null && conversation.owner_user_full_name !== "" || conversation.owner_user_email ? (
                          <div className="flex items-center gap-2">
                            <Avatar className="h-8 w-8 shrink-0">
                              <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">
                                {conversation.owner_user_full_name
                                  ? conversation.owner_user_full_name
                                      .trim()
                                      .split(/\s+/)
                                      .map((p) => p.charAt(0))
                                      .slice(0, 2)
                                      .join("")
                                      .toUpperCase() || (conversation.owner_user_email?.[0] ?? "?").toUpperCase()
                                  : (conversation.owner_user_email?.[0] ?? "?").toUpperCase()}
                              </AvatarFallback>
                            </Avatar>
                            <div className="min-w-0">
                              {conversation.owner_user_full_name != null && conversation.owner_user_full_name !== "" && (
                                <span className="block truncate max-w-[160px]" title={conversation.owner_user_email ?? ""}>
                                  {conversation.owner_user_full_name}
                                </span>
                              )}
                              {conversation.owner_user_email != null && conversation.owner_user_email !== "" && (
                                <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">
                                  {conversation.owner_user_email}
                                </span>
                              )}
                            </div>
                          </div>
                        ) : (
                          "—"
                        )}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                        {formatDate(conversation.created_at)}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                        {formatDate(conversation.last_updated)}
                      </TableCell>
                      <TableCell className="text-sm">
                        {getStatusBadge(conversation.scan_status as ScanStatus)}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          className="cursor-pointer"
                          onClick={() => {
                            setMetadataScan(conversation);
                            setMetadataDialogOpen(true);
                          }}
                        >
                          <Eye className="h-4 w-4 mr-1.5" />
                          View
                        </Button>
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
                            {conversation.scan_status === "success" && (
                              <DropdownMenuItem
                                className="cursor-pointer"
                                onClick={() => router.push(`/${team_id}/sast/${conversation.id}/results?origin=list`)}
                              >
                                <Eye className="h-4 w-4 mr-2" />
                                View Results
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuItem
                              className="cursor-pointer"
                              onClick={() => handleRename(conversation)}
                            >
                              <Pencil className="h-4 w-4 mr-2" />
                              Rename
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="cursor-pointer"
                              onClick={() => handleDelete(conversation)}
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
            <DialogTitle>Rename Conversation</DialogTitle>
            <DialogDescription>
              Enter a new name for this conversation.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Conversation name"
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
            <DialogTitle>Delete Conversation</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete "{selectedConversation?.title}"? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setDeleteDialogOpen(false);
                setSelectedConversation(null);
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

      {/* Scan metadata dialog (depth-1: key / value) */}
      <Dialog open={metadataDialogOpen} onOpenChange={setMetadataDialogOpen}>
        <DialogContent className="max-w-lg max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Scan metadata</DialogTitle>
            <DialogDescription>
              {metadataScan ? `Metadata for "${metadataScan.title}"` : "Scan metadata"}
            </DialogDescription>
          </DialogHeader>
          <div className="py-2">
            {metadataScan?.scan_metadata && typeof metadataScan.scan_metadata === "object" && Object.keys(metadataScan.scan_metadata).length > 0 ? (
              <dl className="space-y-2 text-sm">
                {Object.entries(metadataScan.scan_metadata).map(([key, value]) => (
                  <div key={key} className="flex gap-2 border-b border-zinc-200 dark:border-zinc-700 pb-2">
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300 shrink-0 min-w-[120px]">{key}</dt>
                    <dd className="text-zinc-600 dark:text-zinc-400 break-all">
                      {value !== null && typeof value === "object" ? JSON.stringify(value) : String(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="text-zinc-500 dark:text-zinc-400 text-sm">No metadata for this scan.</p>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Create Scan Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>
              Enter a title for your new SAST scan conversation.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newScanTitle}
              onChange={(e) => setNewScanTitle(e.target.value)}
              placeholder="Scan title"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  confirmCreate();
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setNewScanTitle("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmCreate}
              disabled={!newScanTitle.trim() || createSastConversationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createSastConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


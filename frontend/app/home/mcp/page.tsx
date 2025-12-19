"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
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
import { Badge } from "@/components/ui/badge";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { MCPConversation, deleteMCPConversation, getMCPConversations, renameMCPConversation, createMCPConversation } from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started";


export default function MCPPage() {
  const router = useRouter();
  const [conversations, setConversations] = useState<MCPConversation[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<MCPConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const queryClient = useQueryClient();

  const query = useQuery({ queryKey: ['mcp-conversations'], queryFn: getMCPConversations });

  useEffect(() => {
    if (query.data) {
      setConversations(query.data);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching MCP conversations');
    }
  }, [query.data, query.error]);

  const deleteMCPConversationMutation = useMutation({
    mutationFn: deleteMCPConversation,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations'] });
      toast.success('MCP conversation deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameMCPConversationMutation = useMutation({
    mutationFn: renameMCPConversation,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations'] });
      toast.success('MCP conversation renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const createMCPConversationMutation = useMutation({
    mutationFn: createMCPConversation,
    onSuccess: (conversationId) => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations'] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/home/mcp/${conversationId}`);
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

  const handleRename = (conversation: MCPConversation) => {
    setSelectedConversation(conversation);
    setNewName(conversation.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (conversation: MCPConversation) => {
    setSelectedConversation(conversation);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedConversation && newName.trim()) {
      renameMCPConversationMutation.mutate({ conversation_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false);
      setSelectedConversation(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation) {
      deleteMCPConversationMutation.mutate(selectedConversation.id);
      setDeleteDialogOpen(false);
      setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim()) {
      createMCPConversationMutation.mutate(newScanTitle.trim());
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
                MCP Scans
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your MCP server scan conversations.
              </p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button 
                className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
                onClick={() => setCreateDialogOpen(true)}
              >
                <Plus className="h-4 w-4 mr-2" />
                New Scan
              </Button>
              <Button className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ['mcp-conversations'] })}>
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>

          {/* Conversations Table */}
          {query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                Error in fetching conversations, please try again later
              </p>
            </div>
          ) : query.isLoading ? (
            <div className="flex h-full items-center justify-center">
              <Loader2 className="size-10 animate-spin text-teal-600" />
            </div>
          ) : conversations.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                No scans yet. Create your first MCP scan to get started.
              </p>
              <Button 
                className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
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
                    <TableHead className="w-[300px]">Conversation Name</TableHead>
                    <TableHead>Created At</TableHead>
                    <TableHead>Last Updated</TableHead>
                    <TableHead>Scan Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {conversations.map((conversation) => (
                    <TableRow key={conversation.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                      <TableCell className="font-medium">
                        <Link
                          href={`/home/mcp/${conversation.id}`}
                          className="text-teal-600 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300 hover:underline cursor-pointer"
                        >
                          {conversation.title}
                        </Link>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(conversation.created_at)}
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(conversation.last_updated)}
                      </TableCell>
                      <TableCell>{getStatusBadge(conversation.scan_status as ScanStatus)}</TableCell>
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
              className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
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

      {/* Create Scan Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>
              Enter a title for your new MCP scan conversation.
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
              disabled={!newScanTitle.trim() || createMCPConversationMutation.isPending}
              className="bg-teal-600 hover:bg-teal-700 text-white cursor-pointer"
            >
              {createMCPConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

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
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye } from "lucide-react";
import { useEffect, useState } from "react";
import { DASTConversation, deleteDASTConversation, getDASTConversations, renameDASTConversation, createDASTConversation } from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started";


export default function DASTPage() {
  const router = useRouter();
  const [conversations, setConversations] = useState<DASTConversation[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<DASTConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const queryClient = useQueryClient()

  const query = useQuery({ queryKey: ['dast-conversations'], queryFn: getDASTConversations })

  useEffect(() => {
    if (query.data) {
      setConversations(query.data);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching dast conversations');
    }
  }, [query.data , query.error]);

  const deleteDASTConversationMutation = useMutation({
    mutationFn: deleteDASTConversation,
    onSuccess: (data, variables, context) => {
      queryClient.invalidateQueries({ queryKey: ['dast-conversations'] });
      toast.success('DAST conversation deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  })

  const renameDASTConversationMutation = useMutation({
    mutationFn: renameDASTConversation,
    onSuccess: (data, variables, context) => {
      queryClient.invalidateQueries({ queryKey: ['dast-conversations'] });
      toast.success('DAST conversation renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  })

  const createDASTConversationMutation = useMutation({
    mutationFn: createDASTConversation,
    onSuccess: (conversationId, variables, context) => {
      queryClient.invalidateQueries({ queryKey: ['dast-conversations'] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/home/dast/${conversationId}`);
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

  const handleRename = (conversation: DASTConversation) => {
    setSelectedConversation(conversation);
    setNewName(conversation.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (conversation: DASTConversation) => {
    setSelectedConversation(conversation);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedConversation && newName.trim()) {
      renameDASTConversationMutation.mutate({ conversation_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false);
      setSelectedConversation(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation) {
      deleteDASTConversationMutation.mutate(selectedConversation.id);
      setDeleteDialogOpen(false);
      setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim()) {
      createDASTConversationMutation.mutate(newScanTitle.trim());
    }
  };

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
                DAST Scans
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400">
                Manage and view all your DAST scan conversations.
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
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ['dast-conversations'] })}>
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>

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
                No scans yet. Create your first DAST scan to get started.
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
                    <TableHead className="w-[300px]">Conversation Name</TableHead>
                    <TableHead>Target URL</TableHead>
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
                          href={`/home/dast/${conversation.id}`}
                          className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer"
                        >
                          {conversation.title}
                        </Link>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {conversation.target_url || "N/A"}
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
                            {conversation.scan_status === "success" && (
                              <DropdownMenuItem
                                className="cursor-pointer"
                                onClick={() => router.push(`/home/dast/${conversation.id}/results?origin=list`)}
                              >
                                <Eye className="h-4 w-4 mr-2" />
                                View Results
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuItem
                              onClick={() => handleRename(conversation)}
                              className="cursor-pointer"
                            >
                              <Pencil className="h-4 w-4 mr-2" />
                              Rename
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => handleDelete(conversation)}
                              variant="destructive"
                              className="cursor-pointer"
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
              onClick={() => {
                setRenameDialogOpen(false);
                setNewName("");
              }}
              className="cursor-pointer"
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
              onClick={() => {
                setDeleteDialogOpen(false);
                setSelectedConversation(null);
              }}
              className="cursor-pointer"
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDelete}
              className="cursor-pointer"
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>
              Enter a title for your new DAST scan conversation.
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
              onClick={() => {
                setCreateDialogOpen(false);
                setNewScanTitle("");
              }}
              className="cursor-pointer"
            >
              Cancel
            </Button>
            <Button
              onClick={confirmCreate}
              disabled={!newScanTitle.trim() || createDASTConversationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createDASTConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

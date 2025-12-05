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
import { Plus, MoreVertical, Pencil, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success";

interface Conversation {
  id: number;
  title: string;
  created_at: string;
  last_updated?: string;
  scan_status: ScanStatus;
}

export default function SASTPage() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [loading, setLoading] = useState(true);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<Conversation | null>(null);
  const [newName, setNewName] = useState("");

  // Mock data
  const mockConversations: Conversation[] = [
    {
      id: 1,
      title: "Security Scan - Main Repository",
      created_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
      scan_status: "success",
    },
    {
      id: 2,
      title: "API Endpoint Analysis",
      created_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
      scan_status: "success",
    },
    {
      id: 3,
      title: "Authentication Module Review",
      created_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
      scan_status: "started",
    },
    {
      id: 4,
      title: "Database Query Security",
      created_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
      scan_status: "failure",
    },
    {
      id: 5,
      title: "Frontend Component Scan",
      created_at: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
      scan_status: "pending",
    },
    {
      id: 6,
      title: "Backend Service Analysis",
      created_at: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
      scan_status: "retry",
    },
  ];

  useEffect(() => {
    // TODO: Fetch conversations from API
    // const fetchConversations = async () => {
    //   try {
    //     const response = await fetch('/api/sast/conversations', {
    //       headers: {
    //         'Authorization': `Bearer ${token}`
    //       }
    //     });
    //     const data = await response.json();
    //     setConversations(data);
    //   } catch (error) {
    //     console.error('Error fetching conversations:', error);
    //   } finally {
    //     setLoading(false);
    //   }
    // };
    // fetchConversations();
    
    // Using mock data for now
    setTimeout(() => {
      setConversations(mockConversations);
      setLoading(false);
    }, 500);
  }, []);

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
      pending: { variant: "outline" as const, className: "text-zinc-600 dark:text-zinc-400" },
      started: { variant: "secondary" as const, className: "bg-blue-500 hover:bg-blue-600 text-white" },
      retry: { variant: "secondary" as const, className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      failure: { variant: "destructive" as const, className: "" },
      success: { variant: "default" as const, className: "bg-green-500 hover:bg-green-600 text-white" },
    };

    const config = variants[status];
    const labels = {
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

  const handleRename = (conversation: Conversation) => {
    setSelectedConversation(conversation);
    setNewName(conversation.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (conversation: Conversation) => {
    setSelectedConversation(conversation);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedConversation && newName.trim()) {
      setConversations(
        conversations.map((conv) =>
          conv.id === selectedConversation.id
            ? { ...conv, title: newName.trim() }
            : conv
        )
      );
      setRenameDialogOpen(false);
      setSelectedConversation(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation) {
      setConversations(
        conversations.filter((conv) => conv.id !== selectedConversation.id)
      );
      setDeleteDialogOpen(false);
      setSelectedConversation(null);
    }
  };

  return (
    <div className="flex h-full bg-white dark:bg-zinc-900">
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
            <Link href="/home/sast/new">
              <Button className="bg-teal-600 hover:bg-teal-700 text-white">
                <Plus className="h-4 w-4 mr-2" />
                New Scan
              </Button>
            </Link>
          </div>

          {/* Conversations Table */}
          {loading ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400">Loading...</p>
            </div>
          ) : conversations.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                No scans yet. Create your first SAST scan to get started.
              </p>
              <Link href="/home/sast/new">
                <Button className="bg-teal-600 hover:bg-teal-700 text-white">
                  <Plus className="h-4 w-4 mr-2" />
                  Create New Scan
                </Button>
              </Link>
            </div>
          ) : (
            <div className="border rounded-lg overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[300px]">Conversation Name</TableHead>
                    <TableHead>Created At</TableHead>
                    <TableHead>Scan Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {conversations.map((conversation) => (
                    <TableRow key={conversation.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                      <TableCell className="font-medium">
                        <Link
                          href={`/home/sast/${conversation.id}`}
                          className="text-teal-600 hover:text-teal-700 dark:text-teal-400 dark:hover:text-teal-300 hover:underline"
                        >
                          {conversation.title}
                        </Link>
                      </TableCell>
                      <TableCell className="text-zinc-600 dark:text-zinc-400">
                        {formatDate(conversation.created_at)}
                      </TableCell>
                      <TableCell>{getStatusBadge(conversation.scan_status)}</TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8"
                            >
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => handleRename(conversation)}
                            >
                              <Pencil className="h-4 w-4 mr-2" />
                              Rename
                            </DropdownMenuItem>
                            <DropdownMenuItem
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
              className="bg-teal-600 hover:bg-teal-700 text-white"
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
              onClick={() => {
                setDeleteDialogOpen(false);
                setSelectedConversation(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDelete}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


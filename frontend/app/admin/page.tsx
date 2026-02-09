"use client";

import Link from "next/link";
import { ArrowLeft, Loader2, Shield, UserPlus, Trash2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getAdminUsers,
  getAdminTeams,
  toggleAdminAccess,
  updateTeamCreditBalance,
  createAdminUser,
  deleteUser,
  type AdminUser,
  type AdminTeam,
} from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useState } from "react";

function CreateAdminUserDialog({
  open,
  onOpenChange,
  onSuccess,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}) {
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");

  const createMutation = useMutation({
    mutationFn: createAdminUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      onSuccess();
      onOpenChange(false);
      setEmail("");
      setPassword("");
      setFirstName("");
      setLastName("");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to create admin user");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim() || !firstName.trim() || !lastName.trim()) {
      showErrorToast(new Error("Please fill in all required fields"), "Validation error");
      return;
    }
    createMutation.mutate({ email: email.trim(), password, first_name: firstName.trim(), last_name: lastName.trim() });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-zinc-900 border-zinc-800 sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-zinc-100">Create admin user</DialogTitle>
          <DialogDescription className="text-zinc-400">
            Create a new user with superuser privileges. They will receive an email with their credentials.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4 py-2">
          <div className="space-y-2">
            <Label htmlFor="admin-email" className="text-zinc-300">Email</Label>
            <Input
              id="admin-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@example.com"
              required
              disabled={createMutation.isPending}
              className="bg-zinc-800 border-zinc-700 text-zinc-200"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="admin-password" className="text-zinc-300">Password</Label>
            <Input
              id="admin-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              disabled={createMutation.isPending}
              className="bg-zinc-800 border-zinc-700 text-zinc-200"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="admin-first-name" className="text-zinc-300">First name</Label>
              <Input
                id="admin-first-name"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                placeholder="Jane"
                required
                disabled={createMutation.isPending}
                className="bg-zinc-800 border-zinc-700 text-zinc-200"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="admin-last-name" className="text-zinc-300">Last name</Label>
              <Input
                id="admin-last-name"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                placeholder="Doe"
                required
                disabled={createMutation.isPending}
                className="bg-zinc-800 border-zinc-700 text-zinc-200"
              />
            </div>
          </div>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={createMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white"
            >
              {createMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Create admin user
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteUserConfirmDialog({
  open,
  onOpenChange,
  user,
  onConfirm,
  isDeleting,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: AdminUser | null;
  onConfirm: (user_id: number) => void;
  isDeleting: boolean;
}) {
  if (!user) return null;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-zinc-900 border-zinc-800 sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-zinc-100">Delete user</DialogTitle>
          <DialogDescription className="text-zinc-400">
            Are you sure you want to delete <span className="font-semibold text-zinc-200">{user.user_email}</span>? This will remove the user and all associated team data. This action cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-4">
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isDeleting}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 cursor-pointer"
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            onClick={() => onConfirm(user.user_id)}
            disabled={isDeleting}
            className="bg-red-600 hover:bg-red-700 text-white cursor-pointer"
          >
            {isDeleting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Delete user
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function UsersTable() {
  const queryClient = useQueryClient();
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [deleteConfirmUser, setDeleteConfirmUser] = useState<AdminUser | null>(null);
  const { data: users, isLoading, error } = useQuery({
    queryKey: ["admin-users"],
    queryFn: getAdminUsers,
  });

  const toggleMutation = useMutation({
    mutationFn: toggleAdminAccess,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
    onError: (err) => {
      showErrorToast(err, "Failed to toggle admin access");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
      setDeleteConfirmUser(null);
    },
    onError: (err) => {
      showErrorToast(err, "Failed to delete user");
    },
  });

  const handleToggle = (user_id: number) => {
    toggleMutation.mutate(user_id);
  };

  const handleDeleteClick = (user: AdminUser) => {
    setDeleteConfirmUser(user);
  };

  const handleDeleteConfirm = (user_id: number) => {
    deleteMutation.mutate(user_id);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-zinc-500" />
      </div>
    );
  }
  if (error) {
    return (
      <p className="py-4 text-sm text-red-500">
        Failed to load users. {error instanceof Error ? error.message : "Unknown error"}
      </p>
    );
  }
  return (
    <>
      <CreateAdminUserDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSuccess={() => {}}
      />
      <DeleteUserConfirmDialog
        open={!!deleteConfirmUser}
        onOpenChange={(open) => !open && setDeleteConfirmUser(null)}
        user={deleteConfirmUser}
        onConfirm={handleDeleteConfirm}
        isDeleting={deleteMutation.isPending}
      />
      <div className="flex justify-end mb-4">
        <Button
          onClick={() => setCreateDialogOpen(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white"
        >
          <UserPlus className="w-4 h-4 mr-2" />
          Create admin user
        </Button>
      </div>
      {!users?.length ? (
        <p className="py-4 text-sm text-zinc-500">No users found.</p>
      ) : (
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="text-zinc-300">Email</TableHead>
          <TableHead className="text-zinc-300">Name</TableHead>
          <TableHead className="text-zinc-300">Teams</TableHead>
          <TableHead className="text-zinc-300">Admin Access</TableHead>
          <TableHead className="text-zinc-300 w-[80px]">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {users.map((user: AdminUser) => (
          <TableRow key={user.user_id} className="border-zinc-800">
            <TableCell className="font-medium text-zinc-200">{user.user_email}</TableCell>
            <TableCell className="text-zinc-400">
              {user.user_first_name} {user.user_last_name}
            </TableCell>
            <TableCell className="text-zinc-400">
              {user.user_team_memberships?.length
                ? user.user_team_memberships.map(([, name]) => name).join(", ")
                : "—"}
            </TableCell>
            <TableCell>
              <Switch
                checked={user.user_is_superuser}
                onCheckedChange={() => handleToggle(user.user_id)}
                disabled={toggleMutation.isPending}
              />
            </TableCell>
            <TableCell>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                onClick={() => handleDeleteClick(user)}
                disabled={deleteMutation.isPending}
                title="Delete user"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
      )}
    </>
  );
}

function TeamsTable() {
  const queryClient = useQueryClient();
  const { data: teams, isLoading, error } = useQuery({
    queryKey: ["admin-teams"],
    queryFn: getAdminTeams,
  });
  const [editingTeamId, setEditingTeamId] = useState<number | null>(null);
  const [creditInput, setCreditInput] = useState<string>("");

  const updateMutation = useMutation({
    mutationFn: ({ team_id, credit_balance }: { team_id: number; credit_balance: number }) =>
      updateTeamCreditBalance(team_id, credit_balance),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-teams"] });
      setEditingTeamId(null);
      setCreditInput("");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to update credit balance");
    },
  });

  const handleStartEdit = (team: AdminTeam) => {
    setEditingTeamId(team.team_id);
    setCreditInput(String(team.team_credit_balance));
  };

  const handleSave = (team_id: number) => {
    const val = parseInt(creditInput, 10);
    if (isNaN(val) || val < 0) {
      showErrorToast(new Error("Please enter a valid non-negative number"), "Invalid credit balance");
      return;
    }
    updateMutation.mutate({ team_id, credit_balance: val });
  };

  const handleCancel = () => {
    setEditingTeamId(null);
    setCreditInput("");
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-zinc-500" />
      </div>
    );
  }
  if (error) {
    return (
      <p className="py-4 text-sm text-red-500">
        Failed to load teams. {error instanceof Error ? error.message : "Unknown error"}
      </p>
    );
  }
  if (!teams?.length) {
    return <p className="py-4 text-sm text-zinc-500">No teams found.</p>;
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="text-zinc-300">Team</TableHead>
          <TableHead className="text-zinc-300">Members</TableHead>
          <TableHead className="text-zinc-300">Credit Balance</TableHead>
          <TableHead className="text-zinc-300">Scans</TableHead>
          <TableHead className="text-zinc-300">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {teams.map((team: AdminTeam) => (
          <TableRow key={team.team_id} className="border-zinc-800">
            <TableCell>
              <div>
                <p className="font-medium text-zinc-200">{team.team_name}</p>
                {team.team_description && (
                  <p className="text-xs text-zinc-500 truncate max-w-[200px]">
                    {team.team_description}
                  </p>
                )}
              </div>
            </TableCell>
            <TableCell className="text-zinc-400">
              {team.team_members?.length ? team.team_members.join(", ") : "—"}
            </TableCell>
            <TableCell>
              {editingTeamId === team.team_id ? (
                <div className="flex items-center gap-2">
                  <Input
                    type="number"
                    min={0}
                    value={creditInput}
                    onChange={(e) => setCreditInput(e.target.value)}
                    className="h-8 w-24 bg-zinc-900 border-zinc-700 text-zinc-200"
                  />
                  <Button
                    size="sm"
                    variant="default"
                    onClick={() => handleSave(team.team_id)}
                    disabled={updateMutation.isPending}
                  >
                    Save
                  </Button>
                  <Button size="sm" variant="ghost" onClick={handleCancel}>
                    Cancel
                  </Button>
                </div>
              ) : (
                <span className="text-zinc-300">{team.team_credit_balance}</span>
              )}
            </TableCell>
            <TableCell className="text-zinc-400">
              SAST: {team.sast_scans_count} · IAC: {team.iac_scans_count} · SBOM: {team.sbom_sca_scans_count}
            </TableCell>
            <TableCell>
              {editingTeamId === team.team_id ? null : (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleStartEdit(team)}
                  className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
                >
                  Update Credits
                </Button>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default function AdminPage() {
  return (
    <div className="min-h-screen bg-zinc-950 text-white">
      <header className="sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950/95 backdrop-blur">
        <div className="flex h-14 items-center gap-4 px-6">
          <Link
            href="/home"
            className="flex items-center gap-2 text-sm text-zinc-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Teams
          </Link>
          <div className="flex items-center gap-2 ml-4">
            <Shield className="h-5 w-5 text-blue-500" />
            <span className="font-semibold">Admin Dashboard</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8 space-y-8">
        <Card className="border-zinc-800 bg-zinc-900/50">
          <CardHeader>
            <CardTitle className="text-zinc-100">Users</CardTitle>
            <CardDescription className="text-zinc-400">
              Manage user admin access. Toggle the switch to grant or revoke superuser privileges.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <UsersTable />
          </CardContent>
        </Card>

        <Card className="border-zinc-800 bg-zinc-900/50">
          <CardHeader>
            <CardTitle className="text-zinc-100">Teams</CardTitle>
            <CardDescription className="text-zinc-400">
              Update credit balance for each team. Click &quot;Update Credits&quot; to edit.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TeamsTable />
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

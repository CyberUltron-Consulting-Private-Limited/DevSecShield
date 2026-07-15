"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useRef } from "react";
import {
  getTeam,
  updateTeam,
  removeOrAddTeamMembers,
  deleteTeam,
  type TeamDetails,
  type UpdateTeamData,
  type TicketingIntegrationSettingsData,
} from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Checkbox } from "@/components/ui/checkbox";
import { Loader2, Trash2, UserPlus, UserMinus, Pencil, PenLine, Coins, Users, Info } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { JiraIcon } from "@/components/icons/arcticons-jira";


export default function TeamSettingsPage() {
  const params = useParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const team_id = params?.team_id as string | undefined;

  const { data: team, isLoading } = useQuery({
    queryKey: ["team-details", team_id],
    queryFn: () => getTeam(Number(team_id)),
    enabled: !!team_id,
  });

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraUrl, setJiraUrl] = useState("");
  const [jiraApiToken, setJiraApiToken] = useState("");
  const [selectedEmails, setSelectedEmails] = useState<Set<string>>(new Set());
  const [addMemberEmail, setAddMemberEmail] = useState("");
  const [pendingMemberAction, setPendingMemberAction] = useState<"add" | "remove" | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [creditsInfoDialogOpen, setCreditsInfoDialogOpen] = useState(false);
  const saveFromEditDialogRef = useRef(false);

  useEffect(() => {
    if (team) {
      setName(team.team_name ?? "");
      setDescription(team.team_description ?? "");
      const jira = (team.team_integration_settings as TicketingIntegrationSettingsData | null)?.jira ?? undefined;
      setJiraEmail(jira?.email ?? "");
      setJiraUrl(jira?.url ?? "");
      setJiraApiToken(jira?.api_token ?? "");
    }
  }, [team]);

  const updateTeamMutation = useMutation({
    mutationFn: (data: UpdateTeamData) => updateTeam(Number(team_id), data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["team-details", team_id] });
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      if (saveFromEditDialogRef.current) {
        setEditDialogOpen(false);
        saveFromEditDialogRef.current = false;
      }
    },
    onError: (error) => showErrorToast(error),
  });

  const membersMutation = useMutation({
    mutationFn: (data: { intent: "remove" | "add"; email_ids: string[] }) =>
      removeOrAddTeamMembers(Number(team_id), data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["team-details", team_id] });
      setSelectedEmails(new Set());
      setAddMemberEmail("");
    },
    onError: (error) => showErrorToast(error),
    onSettled: () => setPendingMemberAction(null),
  });

  const deleteTeamMutation = useMutation({
    mutationFn: () => deleteTeam(Number(team_id)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      router.push("/home");
    },
    onError: (error) => showErrorToast(error),
  });

  const handleSaveNameDescription = (fromEditDialog?: boolean) => {
    if (fromEditDialog) saveFromEditDialogRef.current = true;
    updateTeamMutation.mutate({
      name: name.trim() || undefined,
      description: description.trim() || undefined,
      integration_settings: team?.team_integration_settings ?? undefined,
    });
  };

  const handleSaveJira = () => {
    const email = jiraEmail.trim();
    const api_token = jiraApiToken.trim();
    const url = jiraUrl.trim();
    const integration_settings: TicketingIntegrationSettingsData = {
      ...(team?.team_integration_settings && typeof team.team_integration_settings === "object" && !Array.isArray(team.team_integration_settings)
        ? (team.team_integration_settings as TicketingIntegrationSettingsData)
        : {}),
      jira: email && api_token && url ? { email, api_token, url } : null,
    };
    updateTeamMutation.mutate({
      name: team?.team_name ?? undefined,
      description: team?.team_description ?? undefined,
      integration_settings,
    });
  };

  const toggleMemberSelection = (email: string) => {
    setSelectedEmails((prev) => {
      const next = new Set(prev);
      if (next.has(email)) next.delete(email);
      else next.add(email);
      return next;
    });
  };

  const handleRemoveSelected = () => {
    if (selectedEmails.size === 0) return;
    setPendingMemberAction("remove");
    membersMutation.mutate({ intent: "remove", email_ids: Array.from(selectedEmails) });
  };

  const handleAddMember = () => {
    const email = addMemberEmail.trim();
    if (!email) return;
    setPendingMemberAction("add");
    membersMutation.mutate({ intent: "add", email_ids: [email] });
  };

  const handleDeleteTeam = () => {
    deleteTeamMutation.mutate();
    setDeleteDialogOpen(false);
  };

  if (isLoading || !team) {
    return (
      <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-background p-6">
        <Skeleton className="h-10 w-64 mb-4" />
        <Skeleton className="h-32 w-full mb-6" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  const is_team_admin = team.is_team_admin ?? false;

  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-neutral-900">
      <header className="px-6 py-4 border-b border-border flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">
            {team.team_name}{" "}
            {/* <span className="py-1 px-2 rounded-md bg-blue-600 text-white text-sm font-normal">Settings</span> */}
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {team.team_description ?? "Manage team details, members, and integrations."}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="inline-flex items-center gap-1.5 rounded-md bg-muted px-2.5 py-1 text-sm font-medium text-muted-foreground">
            <Coins className="h-4 w-4" />
            {team.team_credit_balance ?? 0} credits
          </span>
          <button
            type="button"
            onClick={() => setCreditsInfoDialogOpen(true)}
            className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted cursor-pointer focus:outline-none focus:ring-2 focus:ring-ring"
            aria-label="How the credit system works"
          >
            <Info className="h-4 w-4" />
          </button>
          <Dialog open={creditsInfoDialogOpen} onOpenChange={setCreditsInfoDialogOpen}>
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle>How the credit system works</DialogTitle>
                <DialogDescription>
                  Credits are used to run scans. Each scan type and configuration uses a different amount of credits.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-3 text-sm text-muted-foreground">
                <p>
                  <strong className="text-foreground">Two-step process:</strong> First, the platform <strong>estimates</strong> how many credits a scan will use. After you confirm, you <strong>start the scan</strong> and that amount is deducted from your team’s balance.
                </p>
                <p>
                  <strong className="text-foreground">Requesting more credits:</strong> If your team needs more credits, email the <strong>CyberUltron</strong> team to request a top-up.
                </p>
              </div>
            </DialogContent>
          </Dialog>
          {is_team_admin && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setEditDialogOpen(true)}
            className="shrink-0 cursor-pointer text-neutral-300 hover:text-neutral-200"
            aria-label="Edit team name and description"
          >
            <PenLine className="size-4" />
          </Button>
          )}
        </div>
      </header>

      <main className="flex-1 p-6 overflow-auto">
        {/* 1. Team members */}
        <section className="pb-6 mb-6 border-b border-border">
          <h2 className="text-lg font-medium flex items-center gap-2">
            <span className="inline-flex items-center justify-center rounded-md bg-blue-600 p-1.5">
              <Users className="h-5 w-5 stroke-1 text-white" />
            </span>
            Team members
          </h2>
          <p className="text-sm text-muted-foreground mb-4 mt-1">
            {is_team_admin
              ? "Add or remove members by email. Only admins can manage members."
              : "List of members in this team."}
          </p>
          <div className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  {is_team_admin && (
                    <TableHead className="w-12">Select</TableHead>
                  )}
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(team.team_members ?? []).map((member) => (
                  <TableRow key={member.email}>
                    {is_team_admin && (
                      <TableCell>
                        {member.role === "admin" ? (
                          <span className="text-muted-foreground text-xs" title="Admin cannot be removed">
                            —
                          </span>
                        ) : (
                          <Checkbox
                            checked={selectedEmails.has(member.email)}
                            onCheckedChange={() => toggleMemberSelection(member.email)}
                          />
                        )}
                      </TableCell>
                    )}
                    <TableCell>{member.email}</TableCell>
                    <TableCell className="capitalize">{member.role}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {is_team_admin && (
              <div className="flex flex-wrap items-end gap-2">
                <div className="space-y-2 flex-1 min-w-[200px]">
                  <Label htmlFor="add-email">Add member by email</Label>
                  <Input
                    id="add-email"
                    type="email"
                    value={addMemberEmail}
                    onChange={(e) => setAddMemberEmail(e.target.value)}
                    placeholder="email@example.com"
                  />
                </div>
                <Button
                  variant="outline"
                  onClick={handleAddMember}
                  disabled={!addMemberEmail.trim() || membersMutation.isPending}
                  className="cursor-pointer"
                >
                  {membersMutation.isPending && pendingMemberAction === "add" && (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  )}
                  <UserPlus className="h-4 w-4 mr-2" />
                  Add
                </Button>
                <Button
                  variant="outline"
                  onClick={handleRemoveSelected}
                  disabled={selectedEmails.size === 0 || membersMutation.isPending}
                  className="text-red-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-950/20 cursor-pointer"
                >
                  {membersMutation.isPending && pendingMemberAction === "remove" && (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  )}
                  <UserMinus className="h-4 w-4 mr-2" />
                  Remove selected ({selectedEmails.size})
                </Button>
              </div>
            )}
          </div>
        </section>

        {/* 3. Integration settings (Jira) */}
        <section className="pb-6 mb-6 border-b border-border">
          <h2 className="text-lg font-medium flex items-center gap-2">
            <span className="inline-flex items-center justify-center rounded-md bg-blue-600 p-1.5">
              <JiraIcon size={20} className="text-white" />
            </span>
            Jira integration
          </h2>
          <p className="text-sm text-muted-foreground mb-4 mt-1">Configure Jira (and other integrations later) for this team. Use an email that has access to the Jira project.</p>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="jira-email">Email (Jira account with project access)</Label>
              <Input
                id="jira-email"
                type="email"
                value={jiraEmail}
                onChange={(e) => setJiraEmail(e.target.value)}
                placeholder="you@example.com"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="jira-url">Jira URL</Label>
              <Input
                id="jira-url"
                type="url"
                value={jiraUrl}
                onChange={(e) => setJiraUrl(e.target.value)}
                placeholder="https://your-domain.atlassian.net"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="jira-token">Jira API token</Label>
              <Input
                id="jira-token"
                type="password"
                value={jiraApiToken}
                onChange={(e) => setJiraApiToken(e.target.value)}
                placeholder="••••••••"
              />
            </div>
            {is_team_admin && (
              <Button
                onClick={handleSaveJira}
                disabled={updateTeamMutation.isPending}
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
              >
                {updateTeamMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Save integration settings
              </Button>
            )}
          </div>
        </section>

        {/* 4. Delete team (bottom, destructive) */}
        {is_team_admin && (
          <section className="w-full pb-6">
            <h2 className="text-lg font-medium text-destructive ">Danger zone</h2>
            <p className="text-sm text-muted-foreground mb-4">
              Deleting this team is permanent. All integrations, scans, and data for this team will be removed.
            </p>
            <Button
              variant="default"
              onClick={() => setDeleteDialogOpen(true)}
              disabled={deleteTeamMutation.isPending}
              className="bg-red-900 cursor-pointer hover:bg-red-800/50 font-normal text-red-300"
            >
              <Trash2 className="h-4 w-4 " />
              Delete team
            </Button>
          </section>
        )}
      </main>

      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit team</DialogTitle>
            <DialogDescription>
              Update the display name and description of this team.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="edit-team-name">Name</Label>
              <Input
                id="edit-team-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Team name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-team-description">Description</Label>
              <Input
                id="edit-team-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Short description"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditDialogOpen(false)} className="cursor-pointer">
              Cancel
            </Button>
            <Button
              onClick={() => handleSaveNameDescription(true)}
              disabled={updateTeamMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {updateTeamMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-destructive">Delete team</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{team.team_name}&quot;? This action cannot be undone.
              All team data, integrations, and scan history will be permanently removed.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialogOpen(false)} className="cursor-pointer">
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteTeam}
              disabled={deleteTeamMutation.isPending}
              className="bg-destructive hover:bg-destructive/90 cursor-pointer"
            >
              {deleteTeamMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Delete team
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import {
  getTeam,
  updateTeam,
  removeOrAddTeamMembers,
  deleteTeam,
  type TeamDetails,
  type UpdateTeamData,
} from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { Loader2, Trash2, UserPlus, UserMinus } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";

interface JiraIntegrationSettings {
  url?: string;
  api_token?: string;
  project_id?: string;
}

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
  const [jiraUrl, setJiraUrl] = useState("");
  const [jiraApiToken, setJiraApiToken] = useState("");
  const [jiraProjectId, setJiraProjectId] = useState("");
  const [selectedEmails, setSelectedEmails] = useState<Set<string>>(new Set());
  const [addMemberEmail, setAddMemberEmail] = useState("");
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  useEffect(() => {
    if (team) {
      setName(team.team_name ?? "");
      setDescription(team.team_description ?? "");
      const jira = (team.team_integration_settings?.jira ?? {}) as JiraIntegrationSettings;
      setJiraUrl(jira.url ?? "");
      setJiraApiToken(jira.api_token ?? "");
      setJiraProjectId(jira.project_id ?? "");
    }
  }, [team]);

  const updateTeamMutation = useMutation({
    mutationFn: (data: UpdateTeamData) => updateTeam(Number(team_id), data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["team-details", team_id] });
      queryClient.invalidateQueries({ queryKey: ["teams"] });
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
  });

  const deleteTeamMutation = useMutation({
    mutationFn: () => deleteTeam(Number(team_id)),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      router.push("/home");
    },
    onError: (error) => showErrorToast(error),
  });

  const handleSaveNameDescription = () => {
    updateTeamMutation.mutate({
      name: name.trim() || undefined,
      description: description.trim() || undefined,
      integration_settings: team?.team_integration_settings ?? undefined,
    });
  };

  const handleSaveJira = () => {
    const integration_settings = {
      ...(team?.team_integration_settings ?? {}),
      jira: {
        url: jiraUrl.trim() || undefined,
        api_token: jiraApiToken.trim() || undefined,
        project_id: jiraProjectId.trim() || undefined,
      },
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
    membersMutation.mutate({ intent: "remove", email_ids: Array.from(selectedEmails) });
  };

  const handleAddMember = () => {
    const email = addMemberEmail.trim();
    if (!email) return;
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
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-background">
      <Card className="rounded-none border-x-0 border-t-0 border-b shadow-none">
        <CardHeader className="px-6 py-4">
          <CardTitle className="text-xl">{team.team_name} <div className="py-1 px-2 inline rounded-md bg-teal-600 text-white w-fit text-sm font-normal">Settings</div></CardTitle>
          <CardDescription>
            {team.team_description ?? "Manage team details, members, and integrations."}
          </CardDescription>
        </CardHeader>
      </Card>

      <main className="flex-1 p-6 overflow-auto space-y-6">
        {/* 1. Name & Description */}
        <Card>
          <CardHeader>
            <CardTitle>Team name & description</CardTitle>
            <CardDescription>Update the display name and description of this team.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="team-name">Name</Label>
              <Input
                id="team-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Team name"
                disabled={!is_team_admin}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="team-description">Description</Label>
              <Input
                id="team-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Short description"
                disabled={!is_team_admin}
              />
            </div>
            {is_team_admin && (
              <Button
                onClick={handleSaveNameDescription}
                disabled={updateTeamMutation.isPending}
                className="bg-teal-600 hover:bg-teal-700 text-white"
              >
                {updateTeamMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Save
              </Button>
            )}
          </CardContent>
        </Card>

        {/* 2. Team members */}
        <Card>
          <CardHeader>
            <CardTitle>Team members</CardTitle>
            <CardDescription>
              {is_team_admin
                ? "Add or remove members by email. Only admins can manage members."
                : "List of members in this team."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  {is_team_admin && (
                    <TableHead className="w-12">Select</TableHead>
                  )}
                  <TableHead>Email</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(team.team_members ?? []).map((email) => (
                  <TableRow key={email}>
                    {is_team_admin && (
                      <TableCell>
                        <Checkbox
                          checked={selectedEmails.has(email)}
                          onCheckedChange={() => toggleMemberSelection(email)}
                        />
                      </TableCell>
                    )}
                    <TableCell>{email}</TableCell>
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
                >
                  <UserPlus className="h-4 w-4 mr-2" />
                  Add
                </Button>
                <Button
                  variant="outline"
                  onClick={handleRemoveSelected}
                  disabled={selectedEmails.size === 0 || membersMutation.isPending}
                  className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950/30"
                >
                  <UserMinus className="h-4 w-4 mr-2" />
                  Remove selected ({selectedEmails.size})
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* 3. Integration settings (Jira) */}
        <Card>
          <CardHeader>
            <CardTitle>Ticketing integrations</CardTitle>
            <CardDescription>Configure Jira (and other integrations later) for this team.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
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
            <div className="space-y-2">
              <Label htmlFor="jira-project">Jira project ID</Label>
              <Input
                id="jira-project"
                value={jiraProjectId}
                onChange={(e) => setJiraProjectId(e.target.value)}
                placeholder="10000"
              />
            </div>
            <Button
              onClick={handleSaveJira}
              disabled={updateTeamMutation.isPending}
              className="bg-teal-600 hover:bg-teal-700 text-white"
            >
              {updateTeamMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Save integration settings
            </Button>
          </CardContent>
        </Card>

        {/* 4. Delete team (bottom, destructive) */}
        {is_team_admin && (
          <Card className="border-destructive/50 bg-destructive/5">
            <CardHeader>
              <CardTitle className="text-destructive">Danger zone</CardTitle>
              <CardDescription>
                Deleting this team is permanent. All integrations, scans, and data for this team will be removed.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                variant="destructive"
                onClick={() => setDeleteDialogOpen(true)}
                disabled={deleteTeamMutation.isPending}
                className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete team
              </Button>
            </CardContent>
          </Card>
        )}
      </main>

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
            <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteTeam}
              disabled={deleteTeamMutation.isPending}
              className="bg-destructive hover:bg-destructive/90"
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

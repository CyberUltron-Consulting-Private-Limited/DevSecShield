"use client";

import { useRouter } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { createTeam, type CreateTeamData } from "@/utils/backend_api";
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
import { Loader2 } from "lucide-react";
import Link from "next/link";

export default function CreateTeamPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const createTeamMutation = useMutation({
    mutationFn: (data: CreateTeamData) => createTeam(data),
    onSuccess: (data: { team_id: number }) => {
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      router.push(`/${data.team_id}`);
    },
    onError: (error) => showErrorToast(error),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    if (!trimmedName) return;
    createTeamMutation.mutate({
      name: trimmedName,
      description: description.trim() || undefined,
    });
  };

  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-background">
      <Card className="rounded-none border-x-0 border-t-0 border-b shadow-none">
        <CardHeader className="px-6 py-4">
          <CardTitle className="text-xl">Create team</CardTitle>
          <CardDescription>
            Create a new team. You will be the admin and can add members later from settings.
          </CardDescription>
        </CardHeader>
      </Card>

      <main className="flex-1 p-6 overflow-auto">
        <Card className="max-w-lg">
          <CardHeader>
            <CardTitle>New team</CardTitle>
            <CardDescription>Enter a name and optional description for the team.</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="team-name">Team name</Label>
                <Input
                  id="team-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Engineering"
                  required
                  disabled={createTeamMutation.isPending}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="team-description">Description (optional)</Label>
                <Input
                  id="team-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Short description"
                  disabled={createTeamMutation.isPending}
                />
              </div>
              <div className="flex gap-2 pt-2">
                <Button
                  type="submit"
                  disabled={!name.trim() || createTeamMutation.isPending}
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                >
                  {createTeamMutation.isPending && (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  )}
                  Create team
                </Button>
                <Button type="button" variant="outline" asChild>
                  <Link href="/home">Cancel</Link>
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}

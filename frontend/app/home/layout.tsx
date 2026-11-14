"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Loader2,
  ShieldCheck,
  Users,
  Plus,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarInset,
} from "@/components/ui/sidebar";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "@/utils/toast";
import {
  useQuery,
  useMutation,
  useQueryClient,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { makeQueryClient } from "@/utils/query_client"
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { getTeams, createTeam, type TeamListItem, type CreateTeamData } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { MobileNavBar } from "@/components/mobile-nav-bar";
import { UserMenu } from "@/components/user-menu";

function CreateTeamTriggerWithDialog() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const createTeamMutation = useMutation({
    mutationFn: (data: CreateTeamData) => createTeam(data),
    onSuccess: (data: { team_id: number }) => {
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      setOpen(false);
      setName("");
      setDescription("");
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
    <>
      <SidebarMenuButton
        onClick={() => setOpen(true)}
        className="text-zinc-300 hover:bg-zinc-800 hover:text-white px-2 py-2 cursor-pointer"
      >
        <Plus className="h-5 w-5" />
        <span>Create team</span>
      </SidebarMenuButton>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create team</DialogTitle>
            <DialogDescription>
              Create a new team. You will be the admin and can add members later from settings.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="create-team-name">Team name</Label>
              <Input
                id="create-team-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Engineering"
                required
                disabled={createTeamMutation.isPending}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="create-team-description">Description (optional)</Label>
              <Input
                id="create-team-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Short description"
                disabled={createTeamMutation.isPending}
              />
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setOpen(false)}
                className="cursor-pointer"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={!name.trim() || createTeamMutation.isPending}
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
              >
                {createTeamMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Create team
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

function TeamsList() {
  const pathname = usePathname();

  const { data: teams, isLoading } = useQuery({
    queryKey: ["teams"],
    queryFn: getTeams,
  });

  if (isLoading) {
    return (
      <div className="px-2 py-4 space-y-2">
        <Skeleton className="h-9 w-full rounded-md" />
        <Skeleton className="h-9 w-full rounded-md" />
        <Skeleton className="h-9 w-[75%] rounded-md" />
      </div>
    );
  }

  if (!teams?.length) {
    return (
      <p className="px-2 py-4 text-sm text-zinc-400">No teams yet.</p>
    );
  }

  return (
    <SidebarMenu>
      {(teams as TeamListItem[]).map((team) => {
        const href = `/${team.team_id}`;
        const isActive = pathname === href || pathname?.startsWith(`${href}/`);
        return (
          <SidebarMenuItem key={team.team_id}>
            <SidebarMenuButton
              asChild
              isActive={isActive}
              className={
                isActive
                  ? "bg-blue-600 text-white hover:bg-blue-600 data-[active=true]:bg-blue-600 cursor-pointer"
                  : "text-zinc-300 hover:bg-zinc-800 hover:text-white active:bg-blue-800 active:text-white px-2 py-2 cursor-pointer"
              }
            >
              <Link href={href}>
                <Users className="h-5 w-5" />
                <span className="truncate">{team.team_name}</span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        );
      })}
    </SidebarMenu>
  );
}

export default function HomeLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const [queryClient] = useState(() => makeQueryClient());

  useEffect(() => {
    if (
      typeof window !== "undefined" &&
      (localStorage.getItem("access_token") == null ||
        localStorage.getItem("access_token") === "")
    ) {
      toast.error("Please login to access this page");
      router.push("/login");
    } else {
      setLoading(false);
    }
  }, [router]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 h-screen">
        <Skeleton className="h-12 w-12 rounded-full" />
        <Skeleton className="h-4 w-32" />
      </div>
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      <SidebarProvider>
        <Sidebar className="">
          <SidebarHeader>
            <div className="px-3 pt-4 pb-2">
              <div className="flex flex-row items-center gap-2">
                <ShieldCheck className="size-9 bg-blue-600 rounded-md p-2" />
                <div className="flex flex-col">
                  <h1 className="text-lg font-medium text-white">
                    DevSec Shield
                  </h1>
                  <p className="text-xs text-zinc-400 w-full text-nowrap">
                    DevSecOps Assistant
                  </p>
                </div>
              </div>
            </div>
          </SidebarHeader>

          <SidebarContent>
            <ScrollArea className="h-full">
              <SidebarGroup className="px-2 pt-1 pb-0">
                <SidebarGroupLabel className="text-zinc-400 text-xs font-semibold px-2 py-2">
                  Teams
                </SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    <SidebarMenuItem>
                      <CreateTeamTriggerWithDialog />
                    </SidebarMenuItem>
                  </SidebarMenu>
                  <TeamsList />
                </SidebarGroupContent>
              </SidebarGroup>
            </ScrollArea>
          </SidebarContent>

          <SidebarFooter>
            <UserMenu />
          </SidebarFooter>
        </Sidebar>

        <SidebarInset className="overflow-auto">
          <MobileNavBar />
          {children}
        </SidebarInset>
      </SidebarProvider>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  );
}

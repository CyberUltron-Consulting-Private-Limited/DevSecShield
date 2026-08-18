"use client";

import Link from "next/link";
import { usePathname, useParams, useRouter } from "next/navigation";
import {
  Code,
  Package,
  FileText,
  Globe,
  ScanLine,
  Bot,
  Link2,
  Home,
  Loader2,
  LogOut,
  ChevronDown,
  Database,
  Box,
  Server,
  Infinity,
  ShieldCheck,
  Settings,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  useQuery,
  useMutation,
  useQueryClient,
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { getUserProfile, logout, getTeams, type TeamListItem } from "@/utils/backend_api";
import { Button } from "@/components/ui/button";
import { Check, Users } from "lucide-react";

function TeamSwitcher() {
  const pathname = usePathname();
  const teamIdFromPath = pathname?.split("/")[1];
  const currentTeamId = teamIdFromPath ? parseInt(teamIdFromPath, 10) : null;

  const { data: teams, isLoading } = useQuery({
    queryKey: ["teams"],
    queryFn: getTeams,
    retry: 1,
  });

  const currentTeam = teams?.find(
    (t) => t.team_id === currentTeamId
  ) as TeamListItem | undefined;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild >
        <Button
          variant="ghost"
          className="w-full has-[>svg]:px-1 justify-between gap-2 h-auto rounded-md hover:bg-zinc-800 text-white hover:text-white cursor-pointer font-medium"
        >
          <div className="flex flex-col items-start gap-0.5 min-w-0 flex-1">
            <div className="flex items-center gap-2 w-full">
              <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-blue-600">
                <Users className="size-4 text-white" />
              </div>
              <span className="truncate text-left flex flex-col gap-0.5">
                {isLoading
                  ? "Loading…"
                  : currentTeam?.team_name ?? "Select team"}
                {currentTeam != null && (
                  <span className="text-xs text-zinc-400 font-mono tabular-nums">
                    {currentTeam.team_credit_balance ?? 0} credits
                  </span>
                )}
              </span>
            </div>
            
          </div>
          <ChevronDown className="size-4 shrink-0 text-zinc-400" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="start"
        side="bottom"
        sideOffset={4}
        className="max-h-[min(var(--radix-dropdown-menu-content-available-height),320px)] overflow-y-auto w-[--radix-dropdown-menu-trigger-width] min-w-56 bg-zinc-800 border-zinc-700"
      >
        {teams?.length ? (
          teams.map((team) => {
            const isActive = team.team_id === currentTeamId;
            return (
              <DropdownMenuItem
                key={team.team_id}
                asChild
                className="cursor-pointer text-zinc-200 focus:bg-zinc-700 focus:text-white"
              >
                <Link
                  href={`/${team.team_id}`}
                  className="flex items-center justify-between gap-2 px-2 py-1.5 w-full"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {isActive ? (
                      <Check className="size-4 shrink-0 text-blue-400" />
                    ) : (
                      <span className="size-4 shrink-0" />
                    )}
                    <span className="truncate">{team.team_name}</span>
                  </div>
                  <span className="text-xs text-zinc-500 font-mono tabular-nums shrink-0">
                    {team.team_credit_balance ?? 0}
                  </span>
                </Link>
              </DropdownMenuItem>
            );
          })
        ) : (
          <div className="px-2 py-4 text-center text-sm text-zinc-400">
            No teams
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

const homeItem = { name: "Home", path: "", icon: Home };

const toolsItems = [
  { name: "SAST", path: "sast", icon: Code },
  { name: "SCA + SBOM", path: "sbom_sca", icon: Package },
  { name: "CBOM", path: "cbom", icon: ShieldCheck },
  { name: "AI BOM", path: "ai_bom", icon: Bot },
  { name: "MCP", path: "mcp", icon: Server },
  { name: "LLM", path: "llm", icon: Box },
  { name: "IAC", path: "iac", icon: FileText },
  { name: "DAST ", path: "dast", icon: Globe },
];

const workflowItems = [
  { name: "CI / CD", path: "ci_cd", icon: Link2 },
  // Guardrails removed from user-facing nav (deprecated — routes retained for soft notice).
];

function UserFooter() {
  const router = useRouter();
  const queryClient = useQueryClient();

  const { data: userProfile, isLoading } = useQuery({
    queryKey: ['user-profile'],
    queryFn: getUserProfile,
    retry: 1,
  });

  const logoutMutation = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      queryClient.clear();
      router.push("/login");
    },
    onError: () => {
      // Even if logout API fails, clear tokens and redirect
      queryClient.clear();
      router.push("/login");
    },
  });

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  const getInitials = (firstName: string | undefined, lastName: string | undefined) => {
    const first = firstName?.charAt(0).toUpperCase() || "";
    const last = lastName?.charAt(0).toUpperCase() || "";
    return first + last || "U";
  };

  if (isLoading) {
    return (
      <div className="p-4">
        <div className="flex items-center gap-3 px-3 py-2">
          <div className="h-10 w-10 rounded-full bg-zinc-700 flex items-center justify-center">
            <Loader2 className="h-4 w-4 animate-spin text-zinc-400" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-zinc-400">Loading...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!userProfile) {
    return null;
  }

  return (
    <div className="">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="w-full flex items-center gap-3 px-3 py-2 rounded-md hover:bg-zinc-800 transition-colors cursor-pointer">
            <div className="h-10 w-10 rounded-full bg-blue-600 flex items-center justify-center text-white font-semibold text-sm shrink-0">
              {getInitials(userProfile.first_name, userProfile.last_name)}
            </div>
            <div className="flex-1 min-w-0 text-left">
              <p className="text-sm font-medium text-white truncate">
                {userProfile.first_name} {userProfile.last_name}
              </p>
              <p className="text-xs text-zinc-400 truncate">{userProfile.email}</p>
            </div>
            <ChevronDown className="h-4 w-4 text-zinc-400 shrink-0" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56 bg-zinc-800">
          <DropdownMenuItem
            onClick={handleLogout}
            className="text-red-400 focus:text-red-300 focus:bg-red-500/10 cursor-pointer bg-zinc-800"
          >
            <LogOut className="h-4 w-4" />
            <span>Logout</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

export default function HomeLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  const [queryClient] = useState(() => new QueryClient())

  const homeHref = team_id ? `/${team_id}` : "#";
  const getItemHref = (path: string) => (team_id && path ? `/${team_id}/${path}` : "#");
  const isHomeActive = !!team_id && (pathname === `/${team_id}` || pathname === `/${team_id}/`);
  const isItemActive = (path: string): boolean => !!(team_id && path && pathname?.startsWith(`/${team_id}/${path}`));

  useEffect(() => {
    if(localStorage.getItem("access_token")==null || localStorage.getItem("access_token")==""){
      toast.error("Please login to access this page")
      router.push("/login")
    }else{
      setLoading(false)
    }
  }, [])

  if (!loading) { 
    return (
    <QueryClientProvider client={queryClient}>
    <SidebarProvider>
      <Sidebar>
          <SidebarHeader>
            <div className="px-2 pt-4 pb-2">
              <TeamSwitcher />
            </div>
          </SidebarHeader>

          <SidebarContent>
            <ScrollArea className="h-full">
              <SidebarGroup className="px-2 pt-1 pb-0">
                <SidebarGroupContent>
                  <SidebarMenu>
                    <SidebarMenuItem>
                      <SidebarMenuButton
                        asChild
                        isActive={isHomeActive}
                        className={
                          isHomeActive
                            ? "bg-blue-600 text-white hover:bg-blue-600 data-[active=true]:bg-blue-600 cursor-pointer"
                            : "text-zinc-300 hover:bg-zinc-800 hover:text-white active:bg-blue-800 active:text-white px-2 py-2 cursor-pointer"
                        }
                      >
                        <Link href={homeHref}>
                          <Home className="h-5 w-5" />
                          <span>{homeItem.name}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>

              <SidebarGroup>
                <SidebarGroupLabel className="text-zinc-400 text-xs font-semibold px-2 py-2">
                  Scanning Utilities
                </SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {toolsItems.map((item) => {
                      const Icon = item.icon;
                      const href = getItemHref(item.path);
                      const isActive = isItemActive(item.path);
                      return (
                        <SidebarMenuItem key={item.path}>
                          <SidebarMenuButton
                            asChild
                            isActive={isActive}
                            className={
                              isActive
                                ? "bg-blue-600 text-white hover:bg-blue-600 data-[active=true]:bg-blue-600 cursor-pointer"
                                : "text-zinc-300 hover:bg-zinc-800 hover:text-white active:bg-blue-800 active:text-white cursor-pointer"
                            }
                          >
                            <Link href={href}>
                              <Icon className="h-5 w-5" />
                              <span>{item.name}</span>
                            </Link>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>

              <SidebarGroup>
                <SidebarGroupLabel className="text-zinc-400 text-xs font-semibold px-2 py-2">
                  Integrations
                </SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {workflowItems.map((item) => {
                      const Icon = item.icon;
                      const href = getItemHref(item.path);
                      const isActive = isItemActive(item.path);
                      return (
                        <SidebarMenuItem key={item.path}>
                          <SidebarMenuButton
                            asChild
                            isActive={isActive}
                            className={
                              isActive
                                ? "bg-blue-600 text-white hover:bg-blue-600 data-[active=true]:bg-blue-600 cursor-pointer"
                                : "text-zinc-300 hover:bg-zinc-800 hover:text-white active:bg-blue-800 active:text-white cursor-pointer"
                            }
                          >
                            <Link href={href}>
                              <Icon className="h-5 w-5" />
                              <span>{item.name}</span>
                            </Link>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      );
                    })}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            </ScrollArea>
          </SidebarContent>

          <SidebarFooter>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  asChild
                  isActive={pathname === "/home"}
                  className={
                    pathname === "/home"
                      ? "bg-blue-600 text-white hover:bg-blue-600 data-[active=true]:bg-blue-600 cursor-pointer"
                      : "text-zinc-300 hover:bg-zinc-800 hover:text-white cursor-pointer"
                  }
                >
                  <Link href="/home">
                    <Users className="h-5 w-5" />
                    <span>Teams</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton
                  asChild
                  isActive={pathname === `/${team_id}/settings` || pathname?.startsWith(`/${team_id}/settings/`)}
                  className={
                    pathname === `/${team_id}/settings` || pathname?.startsWith(`/${team_id}/settings/`)
                      ? "bg-blue-600 text-white hover:bg-blue-600 data-[active=true]:bg-blue-600 cursor-pointer"
                      : "text-zinc-300 hover:bg-zinc-800 hover:text-white cursor-pointer"
                  }
                >
                  <Link href={team_id ? `/${team_id}/settings` : "#"}>
                    <Settings className="h-5 w-5" />
                    <span>Settings</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
            <UserFooter />
          </SidebarFooter>
        </Sidebar>

        <SidebarInset className="overflow-auto">{children}</SidebarInset>
    </SidebarProvider>
    {/* <ReactQueryDevtools initialIsOpen={false} /> */}
    </QueryClientProvider>
  );
} 
else{
  return (
    <div className="flex items-center justify-center h-screen">
      <Loader2 className="w-10 h-10 animate-spin" />
    </div>
  )
}
}

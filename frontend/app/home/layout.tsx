"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
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
  Shield,
  Infinity,
  ShieldCheck,
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
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import {
  useQuery,
  useMutation,
  useQueryClient,
  QueryClient,
  QueryClientProvider,
} from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { getUserProfile, logout } from "@/utils/backend_api";

const homeItem = { name: "Home", href: "/home", icon: Home };

const toolsItems = [
  { name: "SAST", href: "/home/sast", icon: Code },
  { name: "SCA + SBOM", href: "/home/sbom_sca", icon: Package },
  { name: "MCP", href: "/home/mcp", icon: Server },
  { name: "LLM", href: "/home/llm", icon: Box },
  { name: "IAC", href: "/home/iac", icon: FileText },
  { name: "Data Leakage", href: "/home/leakage", icon: Database },
  { name: "AI Agent Discovery", href: "/home/agent_discovery", icon: ScanLine },
  // { name: "DAST ", href: "/home/dast", icon: Globe },
];

const workflowItems = [
  { name: "CI / CD", href: "/home/ci_cd", icon: Link2 },
  { name: "Guardrails", href: "/home/guardrails", icon: Shield },
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
            <div className="h-10 w-10 rounded-full bg-teal-600 flex items-center justify-center text-white font-semibold text-sm shrink-0">
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
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  const queryClient = new QueryClient()

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
      <Sidebar className="border-r border-teal-600 ">
          <SidebarHeader>
            <div className="px-3 pt-4 pb-2">
              <div className="flex flex- row items-center gap-2">
                <ShieldCheck className="size-9 bg-teal-600 rounded-md p-2" />
                <div className="flex flex-col">
                    <h1 className="text-lg font-medium text-white">DevSec Shield</h1>
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
                <SidebarGroupContent>
                  <SidebarMenu>
                    <SidebarMenuItem>
                      <SidebarMenuButton
                        asChild
                        isActive={pathname === "/home"}
                        className={
                          pathname === "/home"
                            ? "bg-teal-600 text-white hover:bg-teal-600 data-[active=true]:bg-teal-600 cursor-pointer"
                            : "text-zinc-300 hover:bg-zinc-800 hover:text-white active:bg-teal-800 active:text-white px-2 py-2 cursor-pointer"
                        }
                      >
                        <Link href={homeItem.href}>
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
                      const isActive = pathname?.startsWith(item.href);
                      return (
                        <SidebarMenuItem key={item.href}>
                          <SidebarMenuButton
                            asChild
                            isActive={isActive}
                            className={
                              isActive
                                ? "bg-teal-600 text-white hover:bg-teal-600 data-[active=true]:bg-teal-600 cursor-pointer"
                                : "text-zinc-300 hover:bg-zinc-800 hover:text-white active:bg-teal-800 active:text-white cursor-pointer"
                            }
                          >
                            <Link href={item.href}>
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
                      const isActive = pathname?.startsWith(item.href);
                      return (
                        <SidebarMenuItem key={item.href}>
                          <SidebarMenuButton
                            asChild
                            isActive={isActive}
                            className={
                              isActive
                                ? "bg-teal-600 text-white hover:bg-teal-600 data-[active=true]:bg-teal-600 cursor-pointer"
                                : "text-zinc-300 hover:bg-zinc-800 hover:text-white active:bg-teal-800 active:text-white cursor-pointer"
                            }
                          >
                            <Link href={item.href}>
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
            <UserFooter />
          </SidebarFooter>
        </Sidebar>

        <SidebarInset className="overflow-auto">{children}</SidebarInset>
    </SidebarProvider>
    <ReactQueryDevtools initialIsOpen={false} />
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

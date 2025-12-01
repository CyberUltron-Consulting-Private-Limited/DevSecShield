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
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarInset,
} from "@/components/ui/sidebar";

const navigationItems = [
  { name: "Home", href: "/home", icon: Home },
  { name: "SAST", href: "/home/sast", icon: Code },
  { name: "SCA + SBOM", href: "/home/sca_sbom", icon: Package },
  { name: "DAST", href: "/home/dast", icon: Globe },
  { name: "MCP", href: "/home/mcp", icon: ScanLine },
  { name: "LLM", href: "/home/llm", icon: Bot },
  { name: "IAC", href: "/home/iac", icon: FileText },
  { name: "Discovery", href: "/home/discovery", icon: ScanLine },
  { name: "Integration", href: "/home/integration", icon: Link2 },
];

export default function HomeLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  return (
    <SidebarProvider>
      <Sidebar className="border-r border-zinc-800  dark:[&_[data-sidebar=sidebar]]:!bg-zinc-950 [&_[data-sidebar=sidebar]]:!text-zinc-300">
          <SidebarHeader className="border-b border-zinc-800">
            <div className="p-4">
              <h1 className="text-xl font-bold text-white">DevSec Shield</h1>
              <p className="text-xs text-zinc-400 mt-1">
                AI-powered DevSecOps Platform
              </p>
            </div>
          </SidebarHeader>

          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  {navigationItems.map((item) => {
                    const Icon = item.icon;
                    const isActive =  item.name!=="Home"  && pathname?.startsWith(item.href)  ;
                    return (
                      <SidebarMenuItem key={item.href}>
                        <SidebarMenuButton
                          asChild
                          isActive={isActive}
                          className={
                            isActive
                              ? "bg-teal-600 text-white hover:bg-teal-600 data-[active=true]:bg-teal-600"
                              : "text-zinc-300 hover:bg-zinc-800 hover:text-white"
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
          </SidebarContent>

          <SidebarFooter className="border-t border-zinc-800">
            <div className="p-4">
              <div className="flex items-center gap-3 px-3 py-2">
                <div className="h-10 w-10 rounded-full bg-teal-600 flex items-center justify-center text-white font-semibold text-sm">
                  JD
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">
                    John Doe
                  </p>
                  <p className="text-xs text-zinc-400 truncate">Security Admin</p>
                </div>
              </div>
            </div>
          </SidebarFooter>
        </Sidebar>

        <SidebarInset className="overflow-auto">{children}</SidebarInset>
      </SidebarProvider>
  );
}


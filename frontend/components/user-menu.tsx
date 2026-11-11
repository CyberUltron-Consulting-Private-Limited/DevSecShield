"use client";

// The user menu at the foot of the app sidebar: Account and Sign out. A team's pages and /home render this one menu
// (#14: /home had its own, which said "Logout" and had no Account entry).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Loader2, LogOut, UserCog } from "lucide-react";
import { useParams, useRouter } from "next/navigation";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { accountPath } from "@/utils/accountForm";
import { getUserProfile, logout } from "@/utils/backend_api";

export function UserMenu() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const teamId = useParams()?.team_id;

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
          {/* change password, sign out everywhere (app/[team_id]/account; /home/account outside a team) */}
          <DropdownMenuItem
            onClick={() => router.push(accountPath(teamId))}
            className="cursor-pointer bg-zinc-800"
            data-testid="user-menu-account"
          >
            <UserCog className="h-4 w-4" />
            <span>Account</span>
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={handleLogout}
            className="text-red-400 focus:text-red-300 focus:bg-red-500/10 cursor-pointer bg-zinc-800"
          >
            <LogOut className="h-4 w-4" />
            <span>Sign out</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

"use client";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ChevronDown, Ticket } from "lucide-react";
import { JiraIcon } from "./icons/arcticons-jira";

export type TicketType = "jira" | null;

export interface FindingSelectionMenuProps {
  /** Number of currently selected rows */
  selectedCount: number;
  /** Called when the user clicks "Clear selection" */
  onClearSelection: () => void;
  /** Called when the user clicks "Create Jira ticket for findings" (only shown when ticketType is "jira") */
  jiraOnClickHandler?: () => void;
  /** Which ticket type to show. "jira" shows the Jira option; null hides it. Extensible for more types later. */
  ticketType: TicketType;
  /** Whether the Jira action is in progress (e.g. mutation pending) */
  isJiraCreating?: boolean;
}

export default function FindingSelectionMenu({
  selectedCount,
  onClearSelection,
  jiraOnClickHandler,
  ticketType,
  isJiraCreating = false,
}: FindingSelectionMenuProps) {
  if (selectedCount <= 0) return null;

  return (
    <div className="flex items-center gap-3 mb-4 p-3 rounded-lg bg-zinc-100 dark:bg-zinc-800/50 ">
      <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
        {selectedCount} selected
      </span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="cursor-pointer gap-1 bg-zinc-800">
            Actions
            <ChevronDown className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          {ticketType === "jira" && jiraOnClickHandler && (
            <DropdownMenuItem
              className="bg-blue-600 text-white cursor-pointer focus:bg-blue-700"
              onClick={jiraOnClickHandler}
              disabled={isJiraCreating}
            >
              <JiraIcon className="text-white stroke-2" />
              {isJiraCreating ? "Creating..." : "Create Jira ticket for findings"}
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <Button
        variant="ghost"
        size="sm"
        className="cursor-pointer text-zinc-600 dark:text-zinc-400"
        onClick={onClearSelection}
      >
        Clear selection
      </Button>
    </div>
  );
}

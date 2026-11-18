"use client";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ChevronDown, Ticket, CheckCircle, EyeOff, Loader2, Circle } from "lucide-react";
import { JiraIcon } from "./icons/arcticons-jira";
import { DropdownMenuSeparator, DropdownMenuLabel } from "@/components/ui/dropdown-menu";
import { InfoTip } from "@/components/ui/info-tip";

export type TicketType = "jira" | null;
export type FindingStatus = "not_started" | "in_progress" | "fixed" | "ignored";

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
  /** Called when the user wants to bulk-change status on selected findings */
  onBulkStatusChange?: (status: FindingStatus) => void;
  /** Whether a bulk status change is in progress */
  isBulkStatusChanging?: boolean;
}

export default function FindingSelectionMenu({
  selectedCount,
  onClearSelection,
  jiraOnClickHandler,
  ticketType,
  isJiraCreating = false,
  onBulkStatusChange,
  isBulkStatusChanging = false,
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
        <InfoTip id="results.selection.actions" className="-ml-2" />
        <DropdownMenuContent align="start" className="bg-zinc-800 border-zinc-700 min-w-[220px]">
          {onBulkStatusChange && (
            <>
              <DropdownMenuLabel className="text-zinc-400 text-xs">Set status</DropdownMenuLabel>
              <DropdownMenuItem
                className="text-zinc-300 focus:bg-zinc-700 cursor-pointer"
                onClick={() => onBulkStatusChange("fixed")}
                disabled={isBulkStatusChanging}
              >
                <CheckCircle className="size-3 mr-2 text-green-400" />
                Mark as fixed
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-zinc-300 focus:bg-zinc-700 cursor-pointer"
                onClick={() => onBulkStatusChange("in_progress")}
                disabled={isBulkStatusChanging}
              >
                <Loader2 className="size-3 mr-2 text-blue-400" />
                Mark as in progress
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-zinc-300 focus:bg-zinc-700 cursor-pointer"
                onClick={() => onBulkStatusChange("ignored")}
                disabled={isBulkStatusChanging}
              >
                <EyeOff className="size-3 mr-2 text-zinc-500" />
                Mark as ignored
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-zinc-300 focus:bg-zinc-700 cursor-pointer"
                onClick={() => onBulkStatusChange("not_started")}
                disabled={isBulkStatusChanging}
              >
                <Circle className="size-3 mr-2 text-zinc-400" />
                Reset to not started
              </DropdownMenuItem>
            </>
          )}
          {ticketType === "jira" && jiraOnClickHandler && (
            <>
              {onBulkStatusChange && <DropdownMenuSeparator className="bg-zinc-700" />}
              <DropdownMenuLabel className="text-zinc-400 text-xs">Integrations</DropdownMenuLabel>
              <DropdownMenuItem
                className="bg-blue-600 text-white cursor-pointer focus:bg-blue-700"
                onClick={jiraOnClickHandler}
                disabled={isJiraCreating}
              >
                <JiraIcon className="text-white stroke-2" />
                {isJiraCreating ? "Creating..." : "Create Jira ticket"}
              </DropdownMenuItem>
            </>
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

"use client";

// #267: the findings tables' "Columns" menu and the per-user visible-columns state behind it (localStorage, read
// after mount so the server render and the first client render agree).

import { useQuery } from "@tanstack/react-query";
import { Columns3 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getUserProfile } from "@/utils/backend_api";

import {
  browserStorage,
  columnPrefsKey,
  defaultColumns,
  columnsForUser,
  MIN_VISIBLE_COLUMNS,
  saveColumns,
  toggleColumn,
  type ColumnDef,
} from "./findingTable";

/**
 * The visible columns of one table for the signed-in user (the layout's cached "user-profile" query). Until the
 * profile has loaded, a change stays in memory (no shared device key); once it loads, that change is stored under the
 * user's key, else the user's stored choice is read.
 */
export function useColumnPrefs<Id extends string>(table: "run" | "scan", defs: readonly ColumnDef<Id>[]) {
  const profile = useQuery({ queryKey: ["user-profile"], queryFn: getUserProfile, staleTime: 5 * 60_000, retry: 1 });
  const key = columnPrefsKey(table, profile.data?.email);
  const [visible, setVisible] = useState<Id[]>(() => defaultColumns(defs));
  const pending = useRef<Id[] | null>(null);
  useEffect(() => {
    if (!key) return;
    setVisible(columnsForUser(browserStorage(), key, defs, pending.current));
    pending.current = null;
  }, [key, defs]);
  const update = useCallback((next: Id[]) => {
    setVisible(next);
    if (key) saveColumns(browserStorage(), key, next);
    else pending.current = next;
  }, [key]);
  return {
    visible,
    isVisible: (id: Id) => visible.includes(id),
    toggle: (id: Id) => update(toggleColumn(defs, visible, id)),
    reset: () => update(defaultColumns(defs)),
  };
}

export function ColumnChooser<Id extends string>({ defs, visible, onToggle, onReset, testId }: {
  /** the columns this table can show now (e.g. without Quantum risk when no row has a grade) */
  defs: readonly ColumnDef<Id>[];
  visible: readonly Id[];
  onToggle: (id: Id) => void;
  onReset: () => void;
  testId: string;
}) {
  const shown = defs.filter((d) => visible.includes(d.id)).length;
  return (
    <DropdownMenu>
      {/* infotip-shared: the menu only shows or hides columns; each column it lists has its own (i) in the table header */}
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-9 gap-1.5 cursor-pointer" data-testid={testId}
                aria-label={`Choose columns (${shown} of ${defs.length} shown)`}>
          <Columns3 className="h-4 w-4" /> Columns
          <span className="text-xs text-zinc-500 tabular-nums">{shown}/{defs.length}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <DropdownMenuLabel className="text-xs text-zinc-500">Columns to show</DropdownMenuLabel>
        {defs.map((d) => {
          const on = visible.includes(d.id);
          return (
            <DropdownMenuCheckboxItem key={d.id} checked={on} className="cursor-pointer"
                                      disabled={on && shown <= MIN_VISIBLE_COLUMNS}
                                      data-testid={`${testId}-${d.id}`}
                                      onSelect={(e) => e.preventDefault()}
                                      onCheckedChange={() => onToggle(d.id)}>
              {d.label}
            </DropdownMenuCheckboxItem>
          );
        })}
        <DropdownMenuSeparator />
        <DropdownMenuItem className="cursor-pointer text-xs" onSelect={onReset} data-testid={`${testId}-reset`}>
          Reset to default columns
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

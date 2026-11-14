"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FieldLabel } from "@/components/ui/info-tip";
import type { InfoTipId } from "@/content/infotips";
import { Plus, Trash2 } from "lucide-react";

export interface PathArraysInputProps {
  /** List of path arrays. Each path is a list of segment strings (e.g. [["src", "*.py"], ["tests"]]). */
  value: string[][];
  /** Called when the user edits the path arrays. */
  onChange: (value: string[][]) => void;
  /** Label shown above the control (e.g. "Exclude paths"). */
  label?: string;
  /** The (i) tip beside the label: what the patterns do in this scan (content/infotips.ts). */
  infoId: InfoTipId;
  /** Placeholder for segment inputs. */
  segmentPlaceholder?: string;
  /** Optional class name for the container. */
  className?: string;
}

function sanitizeSegmentsInPaths(arr: string[][]): string[][] {
  return arr.map((path) => path.map((s) => s.trim()).filter(Boolean));
}

/** Remove empty/whitespace-only strings and empty paths. Use when producing final output (e.g. before API call). */
export function sanitizePathArrays(arr: string[][]): string[][] {
  return sanitizeSegmentsInPaths(arr).filter((path) => path.length > 0);
}

export function PathArraysInput({
  value,
  onChange,
  label = "Path arrays",
  infoId,
  segmentPlaceholder = "segment",
  className = "",
}: PathArraysInputProps) {
  const updatePath = (pathIndex: number, newPath: string[], skipSanitize = false) => {
    if (value.length === 0) {
      const v = pathIndex === 0 ? [newPath] : [];
      onChange(skipSanitize ? v : sanitizeSegmentsInPaths(v));
      return;
    }
    const next = value.map((p, i) => (i === pathIndex ? newPath : p));
    onChange(skipSanitize ? next : sanitizeSegmentsInPaths(next));
  };

  const updateSegment = (pathIndex: number, segmentIndex: number, segmentValue: string) => {
    const path = value[pathIndex] ?? [];
    const newPath = path.map((s, i) => (i === segmentIndex ? segmentValue : s));
    if (segmentIndex >= path.length) {
      newPath.push(segmentValue);
    }
    updatePath(pathIndex, newPath);
  };

  const addSegment = (pathIndex: number) => {
    const path = value[pathIndex] ?? [];
    updatePath(pathIndex, [...path, ""], true);
  };

  const removeSegment = (pathIndex: number, segmentIndex: number) => {
    const path = value[pathIndex] ?? [];
    if (path.length <= 1) return;
    const newPath = path.filter((_, i) => i !== segmentIndex);
    updatePath(pathIndex, newPath);
  };

  const addPath = () => {
    const base = value.length === 0 ? [] : sanitizeSegmentsInPaths(value);
    onChange([...base, [""]]);
  };

  const removePath = (pathIndex: number) => {
    const base = value.length === 0 ? [[]] : value;
    const next = base.filter((_, i) => i !== pathIndex);
    onChange(next.length === 0 ? [] : sanitizeSegmentsInPaths(next));
  };

  const paths = value.length === 0 ? [[]] : value;

  return (
    <div className={className}>
      <FieldLabel infoId={infoId} className="mb-3" labelClassName="text-zinc-300">
        {label}
      </FieldLabel>
      <div className="space-y-3">
        {paths.map((path, pathIndex) => (
          <div
            key={pathIndex}
            className="rounded-md border border-zinc-700 bg-zinc-800/50 p-3 space-y-2"
          >
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-xs text-zinc-500">Path Pattern {pathIndex + 1}</span>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-7 w-7 text-zinc-400 hover:text-red-400 cursor-pointer"
                onClick={() => removePath(pathIndex)}
                aria-label="Remove this path"
                disabled={paths.length <= 1}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="flex flex-wrap gap-2 items-center">
              {(path.length === 0 ? [""] : path).map((segment, segmentIndex) => (
                <div key={segmentIndex} className="flex items-center gap-1">
                  { segmentIndex > 0 && <span className="text-neutral-500 mx-1">/</span> }
                  {/* infotip-shared: every segment box belongs to the pattern field whose label and tip are above */}
                  <Input
                    aria-label={`${label}: pattern ${pathIndex + 1}, segment ${segmentIndex + 1}`}
                    value={segment}
                    onChange={(e) => updateSegment(pathIndex, segmentIndex, e.target.value)}
                    placeholder={segmentPlaceholder}
                    className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 h-8 text-sm min-w-[60px]"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 shrink-0 text-zinc-400 hover:text-red-400 cursor-pointer"
                    onClick={() => removeSegment(pathIndex, segmentIndex)}
                    aria-label="Remove this folder"
                    disabled={(path.length || 1) <= 1}
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              ))}
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-8 gap-1 text-zinc-400 hover:text-white cursor-pointer"
                onClick={() => addSegment(pathIndex)}
              >
                <Plus className="h-3.5 w-3.5" />
                <span className="text-xs">Segment</span>
              </Button>
            </div>
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="w-full border-zinc-700 text-zinc-300 hover:bg-zinc-800 cursor-pointer"
          onClick={addPath}
        >
          <Plus className="h-4 w-4 mr-2" />
          Add path
        </Button>
      </div>
    </div>
  );
}

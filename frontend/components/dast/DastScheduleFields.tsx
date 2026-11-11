"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Plus, X } from "lucide-react";
import type { DastScheduleKind } from "@/utils/backend_api";

export type DastScheduleState = {
  kind: DastScheduleKind;
  times: string[];
  intervalHours: number;
  weekday: number;
  monthday: number;
  onceAt: string;
  cron: string;
};

const KINDS: { value: DastScheduleKind; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "hourly", label: "Hourly (IST)" },
  { value: "every_n_hours", label: "Every N hours (IST)" },
  { value: "daily", label: "Daily (IST)" },
  { value: "weekdays", label: "Weekdays Mon–Fri (IST)" },
  { value: "weekly", label: "Weekly (IST)" },
  { value: "monthly", label: "Monthly (IST)" },
  { value: "once", label: "Run once (IST)" },
  { value: "cron", label: "Custom cron (IST)" },
];

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const CRON_DOW = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

function rangeOptions(start: number, end: number, starLabel: string) {
  const items = [{ value: "*", label: starLabel }];
  for (let i = start; i <= end; i += 1) items.push({ value: String(i), label: String(i) });
  return items;
}

function splitCron(cron: string): [string, string, string, string, string] {
  const parts = (cron || "0 9 * * 1-5").trim().split(/\s+/);
  while (parts.length < 5) parts.push("*");
  return [parts[0], parts[1], parts[2], parts[3], parts[4]];
}

export function DastScheduleFields({
  value,
  onChange,
}: {
  value: DastScheduleState;
  onChange: (next: DastScheduleState) => void;
}) {
  const patch = (partial: Partial<DastScheduleState>) => onChange({ ...value, ...partial });
  const showTimes = ["hourly", "every_n_hours", "daily", "weekdays", "weekly", "monthly"].includes(value.kind);
  const [minute, hour, dom, month, dow] = splitCron(value.cron);

  const setCronPart = (idx: number, part: string) => {
    const next = [...splitCron(value.cron)];
    next[idx] = part;
    patch({ cron: next.join(" ") });
  };

  return (
    <div className="sm:col-span-2 grid gap-3 sm:grid-cols-2">
      <div className="space-y-1.5">
        <Label>Schedule</Label>
        <Select value={value.kind} onValueChange={(v) => patch({ kind: v as DastScheduleKind })}>
          <SelectTrigger className="cursor-pointer">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {KINDS.map((kind) => (
              <SelectItem key={kind.value} value={kind.value}>
                {kind.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {value.kind === "every_n_hours" && (
        <div className="space-y-1.5">
          <Label htmlFor="dast-interval-hours">Every N hours (IST)</Label>
          <Input
            id="dast-interval-hours"
            type="number"
            min={1}
            max={24}
            value={value.intervalHours}
            onChange={(e) => patch({ intervalHours: Number(e.target.value) || 1 })}
          />
        </div>
      )}

      {value.kind === "weekly" && (
        <div className="space-y-1.5">
          <Label>Weekday (IST)</Label>
          <Select value={String(value.weekday)} onValueChange={(v) => patch({ weekday: Number(v) })}>
            <SelectTrigger className="cursor-pointer">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {WEEKDAYS.map((label, idx) => (
                <SelectItem key={label} value={String(idx)}>
                  {label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {value.kind === "monthly" && (
        <div className="space-y-1.5">
          <Label htmlFor="dast-monthday">Day of month (1–28, IST)</Label>
          <Input
            id="dast-monthday"
            type="number"
            min={1}
            max={28}
            value={value.monthday}
            onChange={(e) => patch({ monthday: Number(e.target.value) || 1 })}
          />
        </div>
      )}

      {value.kind === "once" && (
        <div className="space-y-1.5 sm:col-span-2">
          <Label htmlFor="dast-once-at">Run at (IST)</Label>
          <Input
            id="dast-once-at"
            type="datetime-local"
            value={value.onceAt}
            onChange={(e) => patch({ onceAt: e.target.value })}
          />
        </div>
      )}

      {showTimes && (
        <div className="space-y-1.5 sm:col-span-2">
          <Label>Fire times (HH:MM IST)</Label>
          <div className="flex flex-wrap gap-2">
            {value.times.map((time, idx) => (
              <div key={`${time}-${idx}`} className="flex items-center gap-1">
                <Input
                  aria-label={`Fire time ${idx + 1} IST`}
                  className="w-28"
                  value={time}
                  onChange={(e) => {
                    const times = [...value.times];
                    times[idx] = e.target.value;
                    patch({ times });
                  }}
                />
                {value.times.length > 1 && (
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    className="h-8 w-8 cursor-pointer"
                    onClick={() => patch({ times: value.times.filter((_, i) => i !== idx) })}
                    aria-label="Remove this time"
                  >
                    <X className="h-3 w-3" />
                  </Button>
                )}
              </div>
            ))}
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="cursor-pointer"
              onClick={() => patch({ times: [...value.times, "21:00"] })}
            >
              <Plus className="h-3 w-3 mr-1" />
              Add time
            </Button>
          </div>
        </div>
      )}

      {value.kind === "cron" && (
        <>
          <div className="space-y-1.5 sm:col-span-2">
            <Label>Visual cron builder (IST)</Label>
            <div className="grid gap-2 sm:grid-cols-5">
              {[
                { label: "Minute", idx: 0, options: rangeOptions(0, 59, "Every minute") },
                { label: "Hour", idx: 1, options: rangeOptions(0, 23, "Every hour") },
                { label: "Day", idx: 2, options: rangeOptions(1, 31, "Every day") },
                { label: "Month", idx: 3, options: rangeOptions(1, 12, "Every month") },
                {
                  label: "Weekday",
                  idx: 4,
                  options: [{ value: "*", label: "Every day" }, ...CRON_DOW.map((name, i) => ({ value: String(i), label: name }))],
                },
              ].map((field) => (
                <div key={field.label} className="space-y-1">
                  <p className="text-xs text-zinc-500">{field.label}</p>
                  <Select value={[minute, hour, dom, month, dow][field.idx]} onValueChange={(v) => setCronPart(field.idx, v)}>
                    <SelectTrigger className="cursor-pointer">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {field.options.map((opt) => (
                        <SelectItem key={opt.value} value={opt.value}>
                          {opt.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ))}
            </div>
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="dast-cron">5-field cron (IST, 0=Sunday)</Label>
            <Input id="dast-cron" value={value.cron} onChange={(e) => patch({ cron: e.target.value })} placeholder="0 9 * * 1-5" />
          </div>
        </>
      )}
    </div>
  );
}


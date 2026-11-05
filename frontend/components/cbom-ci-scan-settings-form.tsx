"use client";

import { useState } from "react";
import { Loader2, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";

export interface CbomCiScanSettings {
  scan_binaries: boolean;
  include_vendored: boolean;
}

/** CBOM CI/CD scan options: the same two opt-ins as a code scan, used for every scan this integration triggers.
 * The form starts from the saved settings; the page re-keys it when they change. */
export function CbomCiScanSettingsForm({
  saved,
  onSave,
  isSaving,
}: {
  saved: Partial<CbomCiScanSettings> | null | undefined;
  onSave: (settings: CbomCiScanSettings) => void;
  isSaving: boolean;
}) {
  const [includeVendored, setIncludeVendored] = useState(saved?.include_vendored === true);
  const [scanBinaries, setScanBinaries] = useState(saved?.scan_binaries === true);

  const options = [
    {
      id: "cicd-cbom-include-vendored",
      checked: includeVendored,
      set: setIncludeVendored,
      label: "Scan vendored and build directories",
      hint: "Also reads vendor/, dist/, build/ and node_modules/ (third-party code and build output). Off by default.",
    },
    {
      id: "cicd-cbom-scan-binaries",
      checked: scanBinaries,
      set: setScanBinaries,
      label: "Scan binaries",
      hint: "Also reads container images, compiled binaries and firmware in the uploaded archive. Off by default.",
    },
  ];

  return (
    <div className="space-y-4 max-w-xl">
      {options.map((option) => (
        <label key={option.id} htmlFor={option.id} className="flex items-start gap-2 cursor-pointer">
          <Checkbox
            id={option.id}
            checked={option.checked}
            onCheckedChange={(checked) => option.set(checked === true)}
            className="mt-0.5"
          />
          <span className="text-sm text-zinc-700 dark:text-zinc-300">
            {option.label}
            <span className="block text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">{option.hint}</span>
          </span>
        </label>
      ))}
      <Button
        onClick={() => onSave({ scan_binaries: scanBinaries, include_vendored: includeVendored })}
        disabled={isSaving}
        className="cursor-pointer"
      >
        {isSaving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Save className="h-4 w-4 mr-2" />}
        Save scan settings
      </Button>
    </div>
  );
}

"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PathArraysInput } from "@/components/path-arrays-input";
import { Button } from "@/components/ui/button";
import { Filter, Code, Loader2, Save } from "lucide-react";
import type { SastAppLang } from "@/utils/backend_api";

const LANGUAGES: SastAppLang[] = [
  "c",
  "java",
  "php",
  "ruby",
  "rust",
  "swift",
  "python",
  "csharp",
  "kotlin",
  "javascript",
];

export interface SastScanSettingsFormProps {
  appLang: SastAppLang;
  onAppLangChange: (value: SastAppLang) => void;
  excludePathArrays: string[][];
  onExcludePathArraysChange: (value: string[][]) => void;
  onSaveClick: () => void;
  isSaving?: boolean;
}

export function SastScanSettingsForm({
  appLang,
  onAppLangChange,
  excludePathArrays,
  onExcludePathArraysChange,
  onSaveClick,
  isSaving = false,
}: SastScanSettingsFormProps) {
  return (
    <div className="space-y-4">
      {/* Scan scope — exclude path arrays (same order as sast-options-sidebar) */}
      <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none dark:border-zinc-700 dark:bg-zinc-800/50">
        <CardHeader className="pb-2 px-4">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Filter className="h-4 w-4 text-zinc-400 shrink-0" />
            Scan scope
            <InfoTip id="sast.cfg.scope" />
          </CardTitle>
          <CardDescription className="text-zinc-500 text-xs">
            Paths or patterns to exclude from the scan (e.g. vendor, node_modules).
          </CardDescription>
        </CardHeader>
        <CardContent className="px-4 pt-0">
          <PathArraysInput
            label="Exclude path patterns"
            infoId="sast.cfg.exclude"
            value={excludePathArrays}
            onChange={onExcludePathArraysChange}
            segmentPlaceholder="ex: directory or file_name.extension"
          />
        </CardContent>
      </Card>

      {/* App language */}
      <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none dark:border-zinc-700 dark:bg-zinc-800/50">
        <CardHeader className="pb-2 px-4">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Code className="h-4 w-4 text-zinc-400 shrink-0" />
            App language
            {/* infotip-shared: the language field below carries the tip */}
          </CardTitle>
          <CardDescription className="text-zinc-500 text-xs">
            Primary language of the application being scanned (used for analysis).
          </CardDescription>
        </CardHeader>
        <CardContent className="px-4 pt-0">
          <FieldLabel htmlFor="sast-scan-settings-app-lang" infoId="sast.cfg.language" labelClassName="text-zinc-300 text-sm" required>
            Primary app language
          </FieldLabel>
          <Select value={appLang} onValueChange={(value) => onAppLangChange(value as SastAppLang)}>
            <SelectTrigger
              id="sast-scan-settings-app-lang"
              className="bg-zinc-800 border-zinc-700 text-white focus:text-white cursor-pointer mt-1"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-zinc-800 border-zinc-700">
              {LANGUAGES.map((language) => (
                <SelectItem
                  key={language}
                  value={language}
                  className="text-white hover:bg-zinc-700 cursor-pointer"
                >
                  {language.charAt(0).toUpperCase() + language.slice(1)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      <Button
        onClick={onSaveClick}
        disabled={isSaving}
        className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
      >
        {isSaving ? (
          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
        ) : (
          <Save className="w-4 h-4 mr-2" />
        )}
        Save scan settings
      </Button>
    </div>
  );
}

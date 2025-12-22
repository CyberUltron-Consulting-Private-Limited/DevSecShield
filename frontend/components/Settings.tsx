import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { useState, useEffect } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { X, Plus } from "lucide-react";
import { SettingsData } from "@/utils/backend_api";

export const defaultLanguages = ["ARM Assembly", "AppleScript", "C", "C#", "C++", "COBOL", "Erlang", "Fortran", "Go", "Java", "JavaScript", "Kotlin", "Lua", "Mathematica/Wolfram Language", "PHP", "Pascal", "Perl", "PowerShell", "Python", "R", "Ruby", "Rust", "Scala", "Swift", "Visual Basic .NET", "jq"];

interface SettingsFormProps {
  settings: SettingsData;
  onChange: (settings: SettingsData) => void;
  disabled?: boolean;
}


// Helper component for threshold inputs that allows clearing
function ThresholdInput({ 
    value, 
    onChange, 
    disabled, 
    min = 0.1 
  }: { 
    value: number | undefined; 
    onChange: (val: number) => void; 
    disabled: boolean;
    min?: number;
  }) {
    const [localValue, setLocalValue] = useState<string>(value?.toString() ?? min.toString());
    
    useEffect(() => {
      // Sync with external value changes (e.g., when settings are loaded from API)
      setLocalValue(value?.toString() ?? min.toString());
    }, [value, min]);
  
    const validateThreshold = (numValue: number): { valid: boolean; error?: string } => {
      if (numValue === 0) {
        return { valid: false, error: "Threshold cannot be 0" };
      }
      if (numValue < min) {
        return { valid: false, error: `Threshold must be at least ${min}` };
      }
      // Check if it's a whole number (no decimal part)
      if (Number.isInteger(numValue)) {
        return { valid: false, error: "Threshold must be a decimal number (e.g., 0.1, 0.5, 1.2)" };
      }
      return { valid: true };
    };
  
    return (
      <Input
        disabled={disabled}
        type="number"
        step="0.1"
        min={min.toString()}
        value={localValue}
        onChange={(e) => {
          const newValue = e.target.value;
          setLocalValue(newValue);
          // Only update parent if it's a valid number
          const numValue = parseFloat(newValue);
          if (newValue !== "" && !isNaN(numValue)) {
            onChange(numValue);
          }
        }}
        onBlur={(e) => {
          const numValue = parseFloat(e.target.value);
          if (e.target.value === "" || isNaN(numValue)) {
            const validValue = min;
            setLocalValue(validValue.toString());
            onChange(validValue);
            return;
          }
          
          const validation = validateThreshold(numValue);
          if (!validation.valid) {
            toast.error(validation.error || "Invalid threshold value");
            const validValue = min;
            setLocalValue(validValue.toString());
            onChange(validValue);
          } else {
            onChange(numValue);
          }
        }}
      />
    );
  }
  
  const SettingsForm = ({ settings, onChange, disabled = false }: SettingsFormProps) => {
    const isScannerEnabled = (context: any) => context !== null && context !== undefined;
  
    return (
      <div className="space-y-6">
        <Accordion type="multiple" className="w-full">
          {/* Anonymize Context */}
          {isScannerEnabled(settings.anonymize_context) && (
            <AccordionItem value="anonymize">
              <div className="flex items-center justify-between pr-4">
                <AccordionTrigger className="cursor-pointer">Anonymize Context</AccordionTrigger>
                {!disabled && (
                  <div className="flex items-center space-x-2">
                    <Label htmlFor="anonymize-toggle" className="text-sm font-normal cursor-pointer">Enabled</Label>
                    <Switch
                      id="anonymize-toggle"
                      checked={true}
                      onCheckedChange={(checked: boolean) => {
                        if (!checked) {
                          onChange({
                            ...settings,
                            anonymize_context: null as any
                          });
                        }
                      }}
                    />
                  </div>
                )}
              </div>
              <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label className="cursor-pointer">Preamble</Label>
                <Textarea
                  disabled={disabled}
                  value={settings.anonymize_context?.preamble || ""}
                  onChange={(e) => onChange({
                    ...settings,
                    anonymize_context: { ...settings.anonymize_context, preamble: e.target.value }
                  })}
                  placeholder="Directs the LLM to bypass specific content"
                />
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Directs the LLM to bypass specific content. This text will be prepended to the input prompt.
                </p>
              </div>
              <div className="space-y-2">
                <Label className="cursor-pointer">Threshold</Label>
                <ThresholdInput
                  value={settings.anonymize_context?.threshold}
                  onChange={(val) => onChange({
                    ...settings,
                    anonymize_context: { ...settings.anonymize_context, threshold: val }
                  })}
                  disabled={disabled}
                  min={0.1}
                />
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Sets the acceptance threshold for anonymization detection. Must be a decimal number (e.g., 0.1, 0.5, 1.2), cannot be 0 or a whole number. Minimum value is 0.1. Higher values mean stricter detection.
                </p>
              </div>
              <div className="space-y-2">
                <Label className="cursor-pointer">Allowed Names</Label>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-2">
                  List of names that are allowed to be present in the output. These names will not be anonymized.
                </p>
                {(settings.anonymize_context?.allowed_names || []).map((name: string, idx: number) => (
                  <div key={idx} className="flex gap-2">
                    <Input
                      disabled={disabled}
                      value={name}
                      onChange={(e) => {
                        const newNames = [...(settings.anonymize_context?.allowed_names || [])];
                        newNames[idx] = e.target.value;
                        onChange({
                          ...settings,
                          anonymize_context: { ...settings.anonymize_context, allowed_names: newNames }
                        });
                      }}
                    />
                    {!disabled && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => {
                          const newNames = [...(settings.anonymize_context?.allowed_names || [])];
                          newNames.splice(idx, 1);
                          onChange({
                            ...settings,
                            anonymize_context: { ...settings.anonymize_context, allowed_names: newNames }
                          });
                        }}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                ))}
                {!disabled && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => onChange({
                      ...settings,
                      anonymize_context: {
                        ...settings.anonymize_context,
                        allowed_names: [...(settings.anonymize_context?.allowed_names || []), ""]
                      }
                    })}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Add Name
                  </Button>
                )}
              </div>
            </AccordionContent>
          </AccordionItem>
          )}
  
          {/* Anonymize Context Toggle (when disabled) */}
          {!isScannerEnabled(settings.anonymize_context) && !disabled && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <Label className="text-base font-medium cursor-pointer">Anonymize Context</Label>
                <p className="text-sm text-zinc-500 dark:text-zinc-400">Enable anonymization detection</p>
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="anonymize-toggle-off" className="text-sm font-normal cursor-pointer">Disabled</Label>
                <Switch
                  id="anonymize-toggle-off"
                  checked={false}
                  onCheckedChange={(checked: boolean) => {
                    if (checked) {
                      onChange({
                        ...settings,
                        anonymize_context: {
                          preamble: "",
                          threshold: 0.1,
                          allowed_names: []
                        }
                      });
                    }
                  }}
                />
              </div>
            </div>
          )}
  
          {/* Toxicity Context */}
          {isScannerEnabled(settings.toxicity_context) && (
            <AccordionItem value="toxicity">
              <div className="flex items-center justify-between pr-4">
                <AccordionTrigger>Toxicity Context</AccordionTrigger>
                {!disabled && (
                  <div className="flex items-center space-x-2">
                    <Label htmlFor="toxicity-toggle" className="text-sm font-normal cursor-pointer">Enabled</Label>
                    <Switch
                      id="toxicity-toggle"
                      checked={true}
                      onCheckedChange={(checked: boolean) => {
                        if (!checked) {
                          onChange({
                            ...settings,
                            toxicity_context: null as any
                          });
                        }
                      }}
                    />
                  </div>
                )}
              </div>
              <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label className="cursor-pointer">Threshold</Label>
                <ThresholdInput
                  value={settings.toxicity_context?.threshold}
                  onChange={(val) => onChange({
                    ...settings,
                    toxicity_context: { threshold: val }
                  })}
                  disabled={disabled}
                  min={0.1}
                />
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Sets the acceptance threshold for toxicity detection. Must be a decimal number (e.g., 0.1, 0.5, 1.2), cannot be 0 or a whole number. Minimum value is 0.1. Higher values mean stricter detection of toxic content.
                </p>
              </div>
            </AccordionContent>
          </AccordionItem>
          )}
  
          {/* Toxicity Context Toggle (when disabled) */}
          {!isScannerEnabled(settings.toxicity_context) && !disabled && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <Label className="text-base font-medium cursor-pointer">Toxicity Context</Label>
                <p className="text-sm text-zinc-500 dark:text-zinc-400 cursor-pointer">Enable toxicity detection</p>
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="toxicity-toggle-off" className="text-sm font-normal cursor-pointer">Disabled</Label>
                <Switch
                  id="toxicity-toggle-off"
                  checked={false}
                  onCheckedChange={(checked: boolean) => {
                    if (checked) {
                      onChange({
                        ...settings,
                        toxicity_context: { threshold: 0.1 }
                      });
                    }
                  }}
                />
              </div>
            </div>
          )}
  
          {/* Token Limit Context */}
          {isScannerEnabled(settings.tokenlimit_context) && (
            <AccordionItem value="tokenlimit">
              <div className="flex items-center justify-between pr-4">
                <AccordionTrigger>Token Limit Context</AccordionTrigger>
                {!disabled && (
                  <div className="flex items-center space-x-2">
                    <Label htmlFor="tokenlimit-toggle" className="text-sm font-normal cursor-pointer">Enabled</Label>
                    <Switch
                      id="tokenlimit-toggle"
                      checked={true}
                      onCheckedChange={(checked: boolean) => {
                        if (!checked) {
                          onChange({
                            ...settings,
                            tokenlimit_context: null as any
                          });
                        }
                      }}
                    />
                  </div>
                )}
              </div>
              <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label className="cursor-pointer">Max Tokens</Label>
                <Input
                  disabled={disabled}
                  type="number"
                  min="1"
                  value={settings.tokenlimit_context?.max_tokens || 2000}
                  onChange={(e) => {
                    const val = parseInt(e.target.value);
                    const max_tokens = (val && val >= 1) ? val : 2000;
                    onChange({
                      ...settings,
                      tokenlimit_context: { max_tokens }
                    });
                  }}
                />
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Maximum number of tokens allowed in the output. Default is 2000 tokens.
                </p>
              </div>
            </AccordionContent>
          </AccordionItem>
          )}
  
          {/* Token Limit Context Toggle (when disabled) */}
          {!isScannerEnabled(settings.tokenlimit_context) && !disabled && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <Label className="text-base font-medium cursor-pointer">Token Limit Context</Label>
                <p className="text-sm text-zinc-500 dark:text-zinc-400 cursor-pointer">Enable token limit enforcement</p>
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="tokenlimit-toggle-off" className="text-sm font-normal cursor-pointer">Disabled</Label>
                <Switch
                  id="tokenlimit-toggle-off"
                  checked={false}
                  onCheckedChange={(checked: boolean) => {
                    if (checked) {
                      onChange({
                        ...settings,
                        tokenlimit_context: { max_tokens: 2000 }
                      });
                    }
                  }}
                />
              </div>
            </div>
          )}
  
          {/* Prompt Injection Context */}
          {isScannerEnabled(settings.promptinjection_context) && (
            <AccordionItem value="promptinjection">
              <div className="flex items-center justify-between pr-4">
                <AccordionTrigger>Prompt Injection Context</AccordionTrigger>
                {!disabled && (
                  <div className="flex items-center space-x-2">
                    <Label htmlFor="promptinjection-toggle" className="text-sm font-normal cursor-pointer">Enabled</Label>
                    <Switch
                      id="promptinjection-toggle"
                      checked={true}
                      onCheckedChange={(checked: boolean) => {
                        if (!checked) {
                          onChange({
                            ...settings,
                            promptinjection_context: null as any
                          });
                        }
                      }}
                    />
                  </div>
                )}
              </div>
              <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label className="cursor-pointer">Threshold</Label>
                <ThresholdInput
                  value={settings.promptinjection_context?.threshold}
                  onChange={(val) => onChange({
                    ...settings,
                    promptinjection_context: { threshold: val }
                  })}
                  disabled={disabled}
                  min={0.1}
                />
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Sets the acceptance threshold for prompt injection detection. Must be a decimal number (e.g., 0.1, 0.5, 1.2), cannot be 0 or a whole number. Minimum value is 0.1. Higher values mean stricter detection of injection attempts.
                </p>
              </div>
            </AccordionContent>
          </AccordionItem>
          )}
  
          {/* Prompt Injection Context Toggle (when disabled) */}
          {!isScannerEnabled(settings.promptinjection_context) && !disabled && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <Label className="text-base font-medium cursor-pointer">Prompt Injection Context</Label>
                <p className="text-sm text-zinc-500 dark:text-zinc-400 cursor-pointer">Enable prompt injection detection</p>
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="promptinjection-toggle-off" className="text-sm font-normal cursor-pointer">Disabled</Label>
                <Switch
                  id="promptinjection-toggle-off"
                  checked={false}
                  onCheckedChange={(checked: boolean) => {
                    if (checked) {
                      onChange({
                        ...settings,
                        promptinjection_context: { threshold: 0.1 }
                      });
                    }
                  }}
                />
              </div>
            </div>
          )}
  
          {/* Regex Context */}
          {isScannerEnabled(settings.regex_context) && (
            <AccordionItem value="regex">
              <div className="flex items-center justify-between pr-4">
                <AccordionTrigger>Regex Context</AccordionTrigger>
                {!disabled && (
                  <div className="flex items-center space-x-2">
                    <Label htmlFor="regex-toggle" className="text-sm font-normal cursor-pointer">Enabled</Label>
                    <Switch
                      id="regex-toggle"
                      checked={true}
                      onCheckedChange={(checked: boolean) => {
                        if (!checked) {
                          onChange({
                            ...settings,
                            regex_context: null as any
                          });
                        }
                      }}
                    />
                  </div>
                )}
              </div>
              <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label>Redact</Label>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    disabled={disabled}
                    checked={settings.regex_context?.redact || false}
                    onCheckedChange={(checked) => onChange({
                      ...settings,
                      regex_context: { ...settings.regex_context, redact: checked as boolean }
                    })}
                    className="cursor-pointer"
                  />
                  <Label className="cursor-pointer">Redact matched content</Label>
                </div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  When enabled, matched content will be redacted from the output instead of being blocked.
                </p>
              </div>
              <div className="space-y-2">
                <Label className="cursor-pointer">Regex Patterns</Label>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-2">
                  List of regex patterns to be used for detection. Patterns matching these will trigger the regex scanner.
                </p>
                {(settings.regex_context?.regex_patterns || []).map((pattern, idx) => (
                  <div key={idx} className="flex gap-2">
                    <Input
                      disabled={disabled}
                      value={pattern}
                      onChange={(e) => {
                        const newPatterns = [...(settings.regex_context?.regex_patterns || [])];
                        newPatterns[idx] = e.target.value;
                        onChange({
                          ...settings,
                          regex_context: { ...settings.regex_context, regex_patterns: newPatterns }
                        });
                      }}
                      placeholder="Enter regex pattern"
                    />
                    {!disabled && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => {
                          const newPatterns = [...(settings.regex_context?.regex_patterns || [])];
                          newPatterns.splice(idx, 1);
                          onChange({
                            ...settings,
                            regex_context: { ...settings.regex_context, regex_patterns: newPatterns }
                          });
                        }}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                ))}
                {!disabled && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => onChange({
                      ...settings,
                      regex_context: {
                        ...settings.regex_context,
                        regex_patterns: [...(settings.regex_context?.regex_patterns || []), ""]
                      }
                    })}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Add Pattern
                  </Button>
                )}
              </div>
            </AccordionContent>
          </AccordionItem>
          )}
  
          {/* Regex Context Toggle (when disabled) */}
          {!isScannerEnabled(settings.regex_context) && !disabled && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <Label className="text-base font-medium cursor-pointer">Regex Context</Label>
                <p className="text-sm text-zinc-500 dark:text-zinc-400 cursor-pointer">Enable regex pattern matching</p>
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="regex-toggle-off" className="text-sm font-normal cursor-pointer">Disabled</Label>
                <Switch
                  id="regex-toggle-off"
                  checked={false}
                  onCheckedChange={(checked: boolean) => {
                    if (checked) {
                      onChange({
                        ...settings,
                        regex_context: { regex_patterns: [], redact: false }
                      });
                    }
                  }}
                />
              </div>
            </div>
          )}
  
          {/* Code Context */}
          {isScannerEnabled(settings.code_context) && (
            <AccordionItem value="code">
              <div className="flex items-center justify-between pr-4">
                <AccordionTrigger>Code Context</AccordionTrigger>
                {!disabled && (
                  <div className="flex items-center space-x-2">
                    <Label htmlFor="code-toggle" className="text-sm font-normal cursor-pointer">Enabled</Label>
                    <Switch
                      id="code-toggle"
                      checked={true}
                      onCheckedChange={(checked: boolean) => {
                        if (!checked) {
                          onChange({
                            ...settings,
                            code_context: null as any
                          });
                        }
                      }}
                    />
                  </div>
                )}
              </div>
              <AccordionContent className="space-y-4 pt-4">
              <div className="space-y-2">
                <Label>Is Blocked</Label>
                <div className="flex items-center space-x-2">
                  <Checkbox
                    disabled={disabled}
                    checked={settings.code_context?.is_blocked !== false}
                    onCheckedChange={(checked) => onChange({
                      ...settings,
                      code_context: { ...settings.code_context, is_blocked: checked as boolean }
                    })}
                    className="cursor-pointer"
                  />
                  <Label className="cursor-pointer">Block code in output</Label>
                </div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  When enabled, code will be blocked from appearing in the output. When disabled, only languages not in the allowed list will be blocked.
                </p>
              </div>
              <div className="space-y-2">
                <Label className="cursor-pointer">Allowed Languages</Label>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-2">
                  Select programming languages that are allowed to be present in the output. Unselected languages will be blocked.
                </p>
                <div className="border rounded-md p-4 max-h-60 overflow-y-auto space-y-2">
                  {defaultLanguages.map((lang) => (
                    <div key={lang} className="flex items-center space-x-2">
                      <Checkbox
                        disabled={disabled}
                        checked={(settings.code_context?.languages || []).includes(lang)}
                        onCheckedChange={(checked: boolean) => {
                          const currentLangs = settings.code_context?.languages || [];
                          const newLangs = checked
                            ? [...currentLangs, lang]
                            : currentLangs.filter(l => l !== lang);
                          onChange({
                            ...settings,
                            code_context: { ...settings.code_context, languages: newLangs }
                          });
                        }}
                        className="cursor-pointer"
                      />
                      <Label className="cursor-pointer">{lang}</Label>
                    </div>
                  ))}
                </div>
              </div>
            </AccordionContent>
          </AccordionItem>
          )}
  
          {/* Code Context Toggle (when disabled) */}
          {!isScannerEnabled(settings.code_context) && !disabled && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <Label className="text-base font-medium cursor-pointer">Code Context</Label>
                <p className="text-sm text-zinc-500 dark:text-zinc-400 cursor-pointer">Enable code detection and blocking</p>
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="code-toggle-off" className="text-sm font-normal cursor-pointer">Disabled</Label>
                <Switch
                  id="code-toggle-off"
                  checked={false}
                  onCheckedChange={(checked: boolean) => {
                    if (checked) {
                      onChange({
                        ...settings,
                        code_context: { languages: defaultLanguages, is_blocked: true }
                      });
                    }
                  }}
                />
              </div>
            </div>
          )}
  
          {/* Secrets Context */}
          {isScannerEnabled(settings.secrets_context) && (
            <AccordionItem value="secrets">
              <div className="flex items-center justify-between pr-4">
                <AccordionTrigger>Secrets Context</AccordionTrigger>
                {!disabled && (
                  <div className="flex items-center space-x-2">
                    <Label htmlFor="secrets-toggle" className="text-sm font-normal cursor-pointer">Enabled</Label>
                    <Switch
                      id="secrets-toggle"
                      checked={true}
                      onCheckedChange={(checked: boolean) => {
                        if (!checked) {
                          onChange({
                            ...settings,
                            secrets_context: null as any
                          });
                        }
                      }}
                    />
                  </div>
                )}
              </div>
              <AccordionContent className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label className="cursor-pointer">Redact Mode</Label>
                  <Select
                    disabled={disabled}
                    value={settings.secrets_context?.redact_mode || "REDACT_PARTIAL"}
                    onValueChange={(value: "REDACT_PARTIAL" | "REDACT_ALL" | "REDACT_HASH") => onChange({
                      ...settings,
                      secrets_context: { redact_mode: value }
                    })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="REDACT_PARTIAL">Redact Partial</SelectItem>
                      <SelectItem value="REDACT_ALL">Redact All</SelectItem>
                      <SelectItem value="REDACT_HASH">Redact Hash</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">
                    Mode of redaction for detected secrets. Partial redacts only sensitive portions, All redacts the entire secret, Hash replaces with a hash value.
                  </p>
                </div>
              </AccordionContent>
            </AccordionItem>
          )}
  
          {/* Secrets Context Toggle (when disabled) */}
          {!isScannerEnabled(settings.secrets_context) && !disabled && (
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div>
                <Label className="text-base font-medium cursor-pointer">Secrets Context</Label>
                <p className="text-sm text-zinc-500 dark:text-zinc-400 cursor-pointer">Enable secrets detection and redaction</p>
              </div>
              <div className="flex items-center space-x-2">
                <Label htmlFor="secrets-toggle-off" className="text-sm font-normal cursor-pointer">Disabled</Label>
                <Switch
                  id="secrets-toggle-off"
                  checked={false}
                  onCheckedChange={(checked: boolean) => {
                    if (checked) {
                      onChange({
                        ...settings,
                        secrets_context: { redact_mode: "REDACT_PARTIAL" }
                      });
                    }
                  }}
                />
              </div>
            </div>
          )}
        </Accordion>
      </div>
    );
  }
  
  export default SettingsForm;
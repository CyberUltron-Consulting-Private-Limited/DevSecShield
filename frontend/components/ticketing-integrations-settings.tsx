"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { JiraIcon } from "@/components/icons/arcticons-jira";
import { Save, Loader2 } from "lucide-react";

export interface TicketingIntegrationsSettingsProps {
  /** Current Jira project ID value */
  jiraProjectId: string;
  /** Called when the user types in the Jira project ID field */
  onJiraProjectIdChange: (value: string) => void;
  /** Called when the user clicks Save */
  onSave: () => void;
  /** Whether a save request is in progress */
  isSaving: boolean;
  /** Unique id for the Jira project ID input (for a11y). e.g. "sast-jira-project-id" */
  inputId?: string;
}

export default function TicketingIntegrationsSettings({
  jiraProjectId,
  onJiraProjectIdChange,
  onSave,
  isSaving,
  inputId = "ticketing-jira-project-id",
}: TicketingIntegrationsSettingsProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Ticketing integrations</CardTitle>
        <CardDescription>
          Connect this scan to ticketing systems. Configure Jira project to send findings.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Accordion type="single" collapsible className="w-full">
          <AccordionItem value="jira">
            <AccordionTrigger className="cursor-pointer">
              <span className="flex items-center gap-2">
                <span className="inline-flex items-center justify-center rounded-md bg-blue-600 p-1.5">
                  <JiraIcon size={20} className="text-white" />
                </span>
                Jira
              </span>
            </AccordionTrigger>
            <AccordionContent>
              <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-4">
                Send scan findings to Jira as issues. Set the Jira project ID to link this scan to a project.
              </p>
              <div className="space-y-2 max-w-sm">
                <Label htmlFor={inputId}>Jira project ID</Label>
                <Input
                  id={inputId}
                  value={jiraProjectId}
                  onChange={(e) => onJiraProjectIdChange(e.target.value)}
                  placeholder="e.g. 10000"
                />
                <Button
                  onClick={onSave}
                  disabled={isSaving}
                  className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer mt-2"
                >
                  {isSaving ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Save className="w-4 h-4 mr-2" />
                      Save
                    </>
                  )}
                </Button>
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
}

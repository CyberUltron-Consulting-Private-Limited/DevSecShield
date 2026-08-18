"use client";

/**
 * Soft user-facing replacement when Guardrails product UI is deprecated.
 * Deep links land here instead of the former integration management UI.
 */
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

let warnedOnce = false;

export function GuardrailsDeprecatedNotice() {
  const params = useParams();
  const teamId = params?.team_id as string | undefined;
  const homeHref = teamId ? `/${teamId}` : "/home";

  useEffect(() => {
    if (!warnedOnce) {
      warnedOnce = true;
      console.warn(
        "[deprecated] Guardrails product UI is removed from user-facing surfaces. APIs/workers may remain for legacy callers."
      );
    }
  }, []);

  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] p-6">
      <Card className="max-w-lg w-full">
        <CardHeader>
          <CardTitle>Guardrails is no longer available</CardTitle>
          <CardDescription>
            The Guardrails product UI has been removed from DevSecShield. Existing API
            integrations may continue to work for legacy callers, but this surface is
            deprecated and is not available in the product.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild>
            <Link href={homeHref}>Back to team home</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

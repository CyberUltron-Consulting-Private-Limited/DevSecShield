"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function TeamPage({
  params,
}: {
  params: Promise<{ team_id: string }>;
}) {
  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-background">
      <Card className="rounded-none border-x-0 border-t-0 border-b shadow-none">
        <CardHeader className="px-6 py-4">
          <CardTitle className="text-xl">Team Dashboard</CardTitle>
          <CardDescription>
            Overview and charts for this team. Replace placeholders with your
            charts later.
          </CardDescription>
        </CardHeader>
      </Card>

      <main className="flex-1 p-6 overflow-auto">
        {/* Placeholder for charts — add your charts here later */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          <Card className="min-h-[200px] flex flex-col">
            <CardContent className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
              Chart 1
            </CardContent>
          </Card>
          <Card className="min-h-[200px] flex flex-col">
            <CardContent className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
              Chart 2
            </CardContent>
          </Card>
          <Card className="min-h-[200px] flex flex-col">
            <CardContent className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
              Chart 3
            </CardContent>
          </Card>
        </div>
        <Card className="mt-6 min-h-[280px] flex flex-col">
          <CardContent className="flex-1 flex items-center justify-center text-muted-foreground text-sm">
            Chart 4 (wider)
          </CardContent>
        </Card>
      </main>
    </div>
  );
}


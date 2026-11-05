"use client";

/**
 * Shown on the routes of a product this installation does not serve, instead of a page that waits for an API that
 * does not exist. Data leakage: the backend has no /leakage routes and the product is not in the navigation, but
 * /<team>/leakage still loaded, called GET /leakage/conversations (404 x3, then on every Refresh) and kept a
 * spinner (found on the local production stack, round 5).
 */
import Link from "next/link";
import { useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function ProductUnavailableNotice({ product }: { product: string }) {
  const params = useParams();
  const teamId = params?.team_id as string | undefined;
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] p-6" data-testid="product-unavailable">
      <Card className="max-w-lg w-full">
        <CardHeader>
          <CardTitle>{product} is not available</CardTitle>
          <CardDescription>
            {product} scans are not offered on this installation. Use the scanners in the menu on the left; for
            questions about {product.toLowerCase()} scanning contact your DevSecShield administrator.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild>
            <Link href={teamId ? `/${teamId}` : "/home"}>Back to team home</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

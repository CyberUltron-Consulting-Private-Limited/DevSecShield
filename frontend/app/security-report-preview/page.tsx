import { notFound } from "next/navigation";
import SecurityReportTemplate from "@/components/SecurityReportTemplate";

/**
 * Local design preview for SecurityReportTemplate.
 * Returns 404 in production so mock findings are not publicly reachable.
 */
export default function SecurityReportPreviewPage() {
  if (process.env.NODE_ENV === "production") {
    notFound();
  }
  return <SecurityReportTemplate />;
}

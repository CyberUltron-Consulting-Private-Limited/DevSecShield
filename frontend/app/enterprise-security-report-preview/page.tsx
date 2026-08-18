import { notFound } from "next/navigation";
import EnterpriseSecurityReport from "@/components/EnterpriseSecurityReport";

/**
 * Local design preview for EnterpriseSecurityReport.
 * Returns 404 in production so mock findings are not publicly reachable.
 */
export default function EnterpriseSecurityReportPreviewPage() {
  if (process.env.NODE_ENV === "production") {
    notFound();
  }
  return <EnterpriseSecurityReport />;
}

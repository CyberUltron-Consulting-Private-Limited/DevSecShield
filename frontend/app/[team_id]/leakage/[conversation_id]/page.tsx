"use client";

/** Data leakage has no backend routes on this installation (see ProductUnavailableNotice); the former page is in git. */
import { ProductUnavailableNotice } from "@/components/ProductUnavailableNotice";

export default function LeakageConversationPage() {
  return <ProductUnavailableNotice product="Data leakage" />;
}

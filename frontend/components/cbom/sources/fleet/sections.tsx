"use client";

// The Fleet tab's sections, in display order. Each shows only while its server flag is on (GET /fleet/status).
// F1.3 and F1.4 add one import under their "import" marker and one entry under their marker in FLEET_SECTIONS
// (F1 contract, section 5); nothing else in this file changes for them.

import type { ComponentType } from "react";

import type { CbomFleetStatus } from "@/utils/api/cbom_fleet";

// F1.2 import
import CredentialsSection from "./CredentialsSection";
import InventorySection from "./InventorySection";
import PoliciesSection from "./PoliciesSection";
// F1.3 import
// F1.4 import

export interface FleetSectionProps {
  teamId: number;
  status: CbomFleetStatus;
}

export interface FleetSection {
  id: string;
  flag: keyof CbomFleetStatus;
  Component: ComponentType<FleetSectionProps>;
}

export const FLEET_SECTIONS: FleetSection[] = [
  // F1.2
  { id: "inventory", flag: "inventory", Component: InventorySection },
  { id: "policies", flag: "policies", Component: PoliciesSection },
  { id: "credentials", flag: "policies", Component: CredentialsSection },
  // F1.3
  // F1.4
];

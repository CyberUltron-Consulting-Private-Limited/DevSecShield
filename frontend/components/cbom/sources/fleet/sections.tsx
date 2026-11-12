"use client";

// The Fleet tab's sections, in display order. Each shows only while its server flag is on (GET /fleet/status).
// F1.3 and F1.4 add one import under their "import" marker and one entry under their marker in FLEET_SECTIONS
// (F1 contract, section 5); nothing else in this file changes for them.

import type { ComponentType } from "react";

import type { CbomFleetStatus } from "@/utils/api/cbom_fleet";

// F1.2 import
// F1.3 import
// F1.4 import
import { SshCaFleetSection } from "./SshCaSection";

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
  // F1.3
  // F1.4
  { id: "ssh-ca", flag: "ssh_ca", Component: SshCaFleetSection },
];

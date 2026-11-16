/**
 * Every (i) tip with its label and text, in one object: for the unit tests and the e2e harness only. It imports every
 * area statically, so app code must never import it (content/infotipsBundle.test.ts fails if a page reaches it).
 */
import { TIP_AREAS, type TipArea } from "./areas";
import { INFO_TIP_LABELS, type InfoTipId } from "./labels";
import type { InfoTipEntry, TipAreaText } from "./types";

import aibom from "./text/aibom";
import cbomGrade from "./text/cbom-grade";
import cbomResults from "./text/cbom-results";
import cbomRun from "./text/cbom-run";
import cbomScans from "./text/cbom-scans";
import cbsrcCloud from "./text/cbsrc-cloud";
import cbsrcCommon from "./text/cbsrc-common";
import cbsrcEvidence from "./text/cbsrc-evidence";
import cbsrcNetwork from "./text/cbsrc-network";
import cbsrcNodes from "./text/cbsrc-nodes";
import cbsrcRun from "./text/cbsrc-run";
import cbsrcServers from "./text/cbsrc-servers";
import cbsrcSshCa from "./text/cbsrc-ssh-ca";
import cbsrcWorkloads from "./text/cbsrc-workloads";
import dast from "./text/dast";
import fleet from "./text/fleet";
import iac from "./text/iac";
import integrations from "./text/integrations";
import llm from "./text/llm";
import mcp from "./text/mcp";
import repos from "./text/repos";
import results from "./text/results";
import sast from "./text/sast";
import sbom from "./text/sbom";
import scan from "./text/scan";
import settings from "./text/settings";
import team from "./text/team";

/** Each area's text module, as load.ts would load it. */
export const AREA_TEXT: Record<TipArea, TipAreaText> = {
  scan,
  results,
  sast,
  sbom,
  iac,
  dast,
  aibom,
  mcp,
  llm,
  team,
  settings,
  integrations,
  "cbom-scans": cbomScans,
  "cbom-results": cbomResults,
  "cbom-grade": cbomGrade,
  "cbom-run": cbomRun,
  "cbsrc-common": cbsrcCommon,
  "cbsrc-nodes": cbsrcNodes,
  "cbsrc-servers": cbsrcServers,
  "cbsrc-workloads": cbsrcWorkloads,
  "cbsrc-cloud": cbsrcCloud,
  "cbsrc-network": cbsrcNetwork,
  "cbsrc-evidence": cbsrcEvidence,
  "cbsrc-run": cbsrcRun,
  "cbsrc-ssh-ca": cbsrcSshCa,
  fleet,
  repos,
};

/** Every tip, label and text, in the order of labels.ts. An id whose text is missing has empty fields (the test fails it). */
export const INFO_TIPS = Object.fromEntries(
  (Object.keys(INFO_TIP_LABELS) as InfoTipId[]).map((id) => {
    const text = TIP_AREAS.map((a) => AREA_TEXT[a][id]).find(Boolean);
    return [id, { label: INFO_TIP_LABELS[id], what: text?.what ?? "", why: text?.why ?? "", example: text?.example ?? "" }];
  }),
) as Record<InfoTipId, InfoTipEntry>;

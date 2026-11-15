/**
 * (i) tip text of the "cbsrc-run" area (ids: cbsrc.rr.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run (components/cbom/sources/ReviewRunTab.tsx)
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:231-307,317, frontend/components/cbom/sources/ReviewRunTab.tsx:317 — one row per source group
  "cbsrc.rr.coverage": {
    what: "Every kind of source and what a run would collect from it: how much is in scope, what reaches it (scan nodes, ZeroShield's cloud or questionnaires), failed tests, the credits it costs per run and whether it is ready.",
    why: "Shows at a glance which parts of the estate the next run covers and which it leaves out.",
    example: "Servers · 3 sources, 612 targets · node-dc1 · No failed tests · 122.40 (0.2 per target) · Ready.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:323 — the source group
  "cbsrc.rr.col.source": {
    what: "The group of sources: servers, Kubernetes, databases, cloud, network, identity, evidence or code scans.",
    why: "A run is started per group with the boxes under Start a scan.",
    example: "Databases.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:324 — what the group covers
  "cbsrc.rr.col.in_scope": {
    what: "How much of the group a run would cover: sources, targets, accounts or areas.",
    why: "Zero in scope means the group adds nothing to the CBOM yet.",
    example: "2 sources, 4 databases.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:325 — scan nodes or ZeroShield's cloud
  "cbsrc.rr.col.through": {
    what: "What does the collecting: the scan nodes for in-network sources, or ZeroShield's cloud for cloud accounts, CT logs and identity providers.",
    why: "An offline node here means that group's jobs wait.",
    example: "node-dc1, node-dr1.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:239, frontend/components/cbom/sources/ReviewRunTab.tsx:263, frontend/components/cbom/sources/ReviewRunTab.tsx:307 — estimated credits per run for the group
  "cbsrc.rr.col.credits": {
    what: "The credits one run of this group is estimated to charge; code scans are charged per scan and evidence costs nothing.",
    why: "Credits come off the team balance when the run starts and are refunded for jobs that fail or expire.",
    example: "4.00 for one AWS account (4 credits per account per run).",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:326 — ready, needs attention or not set up
  "cbsrc.rr.col.status": {
    what: "Ready, a count of issues to fix (for example an offline node or a failed test), Not configured, or for evidence the number of gaps.",
    why: "Groups that are not ready are skipped and listed below with the fix.",
    example: "1 issue: a source has a failed connection test.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:357 — sources the plan would skip
  "cbsrc.rr.skipped": {
    what: "Sources the next run would skip, each with the reason: an offline or missing node, a failed or missing test, a missing credential, or a closed scan window.",
    why: "A skipped source is a gap in the CBOM; fixing it before starting saves a second run.",
    example: "dc-mumbai-windows: the connection test failed (Login failed).",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:393-404 — jobs, run record, proof trail, evidence gaps
  "cbsrc.rr.after": {
    what: "What a run produces: collection jobs per source for your scan nodes, a run record with the credits charged and refunded, a proof trail (audit log, node source IPs, the AWS role's CloudTrail calls) and evidence gaps listed as Q0, never assumed safe.",
    why: "The proof trail lets your SOC and auditors confirm exactly what was touched.",
    example: "Run #42: 2 databases, 1 AWS account and 32 server targets: 12.40 credits charged; 1.00 refunded for a database job that failed.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:630, frontend/components/cbom/sources/ReviewRunTab.tsx:53-59,408 — choose groups, estimate the credits, start
  "cbsrc.rr.start": {
    what: "Choose which groups to collect, estimate the credits, confirm the SOC agreement for network scans, then start the run.",
    why: "Credits are charged when the run starts; the estimate shows the cost and what will be skipped first.",
    example: "Servers (612 targets) and one AWS account: 122.40 + 4.00 = 126.40 credits.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:53-59,636, frontend/components/cbom/sources/ReviewRunTab.tsx:633-639 — one box per group; how many sources are ready
  "cbsrc.rr.include": {
    what: "Tick each group of sources to collect in this run; the count shows how many of its sources are ready.",
    why: "Leave out groups whose systems are in a change freeze.",
    example: "Servers · 3 ready.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:698-709 — required when Network is included
  "cbsrc.rr.soc_ack": {
    what: "Confirm that your SOC has agreed the network ranges and scan windows. Required when the run includes Network.",
    why: "Active network probing without SOC agreement is often treated as an incident.",
    example: "Tick after the SOC acknowledged ranges 10.20.0.0/16 and the 22:00-06:00 window.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:423 — the 50 most recent runs
  "cbsrc.rr.runs": {
    what: "The 50 most recent collection runs of this team, newest first, with their status, jobs, assets and credits. Open Results for a run's findings, or Compare two finished runs.",
    why: "Comparing runs shows what changed: new weak keys, fixed ones, expired certificates.",
    example: "Run #42 · Done · 9 done · 1,284 assets · 12.40 charged / 1.00 refunded.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:449 — run number
  "cbsrc.rr.col.run": {
    what: "The run's number, unique within ZeroShield.",
    why: "Reports and exports name the run by this number.",
    example: "#42, the run started on 13 Nov.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:450 — when the run was created
  "cbsrc.rr.col.started": {
    what: "When the run was started.",
    why: "Findings reflect the estate at this time.",
    example: "13 Nov 2026, 11:05 pm IST.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:118-125, backend/utilities/cbom_sources/jobs.py:121-133 — jobs.py run status: partial also when every job succeeded but one reported a partial or failed outcome
  "cbsrc.rr.col.run_status": {
    what: "Queued, Running, Done (every job succeeded completely), Partial (some jobs failed or expired, or a job finished but reported a partial or failed outcome), Failed or Cancelled.",
    why: "A Partial run's results miss the sources whose jobs failed.",
    example: "Partial: 8 of 9 jobs done, 1 expired.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:156-160 — job counts by status
  "cbsrc.rr.col.jobs": {
    what: "The run's collection jobs (one per source) counted by status.",
    why: "Waiting jobs usually mean an offline scan node.",
    example: "8 done · 1 failed.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:469-471 — assets collected
  "cbsrc.rr.col.assets": {
    what: "How many crypto assets the run collected: certificates, keys, protocols, libraries and other items.",
    why: "A sudden drop between runs can mean a source stopped reporting.",
    example: "1,284.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:472-474, backend/utilities/cbom_sources/jobs.py:86-108 — charged and refunded
  "cbsrc.rr.col.run_credits": {
    what: "Credits charged when the run started, and credits refunded for jobs that failed, expired or were cancelled.",
    why: "You pay only for jobs that completed.",
    example: "12.40 charged / 1.00 refunded.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:28 — scan node or ZeroShield cloud
  "cbsrc.rr.job.runs_on": {
    what: "Where the job ran: a scan node, or ZeroShield's cloud for cloud accounts, CT logs and identity providers.",
    why: "Points you at the node to check when a job fails.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:101-108 — waiting, running, done, failed, cancelled, expired
  "cbsrc.rr.job.status": {
    what: "Waiting (for its node or window), Running, Done, Failed, Cancelled or Expired (never claimed in time; refunded). The note below says why it waits.",
    why: "Expired and failed jobs are refunded and their source has no new results in this run.",
    example: "Waiting · outside the scan window; starts at 22:00.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:30 — assets the job collected
  "cbsrc.rr.job.assets": {
    what: "How many assets this job collected from its source.",
    why: "Zero from a source that had assets before deserves a look.",
    example: "212 from dc-mumbai-linux.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:31 — charged for the job; refunded marker
  "cbsrc.rr.job.credits": {
    what: "The credits charged for this job, marked refunded when it failed, expired or was cancelled.",
    why: "Shows which part of the run's cost came back.",
    example: "25.60 refunded: a 128-target server job that expired.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:32 — how many times the job was tried
  "cbsrc.rr.job.attempts": {
    what: "How many times a node tried this job. A job is retried after a transient failure.",
    why: "Many attempts point at a flaky network path or an overloaded node.",
    example: "2: the first try timed out, the second finished.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:33 — the job's last error
  "cbsrc.rr.job.error": {
    what: "The last error the job reported, if any.",
    why: "It names the exact failure to fix before the next run.",
    example: "connect timeout to 10.20.0.17:22.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:79 — sources skipped at start
  "cbsrc.rr.skipped_start": {
    what: "Sources that were not queued when the run started, each with the reason.",
    why: "They are not in this run's results and were not charged.",
    example: "dc-mumbai-windows: the scan node was offline.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, run details
  // src: frontend/components/cbom/results/RunJobsTable.tsx:27 — one job per source
  "cbsrc.rr.job.source": {
    what: "The source this job collected from; each source in the run has one job.",
    why: "Open the source's tab to fix a failed job.",
    example: "dc-mumbai-linux.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, business criticality
  // src: backend/utilities/cbom_sources/posture.py:12-14, backend/utilities/cbom_sources/posture.py:43-47 — impact weight x criticality x exposure
  "cbsrc.rr.criticality": {
    what: "Per source: business criticality (Low x0.5, Medium x1 by default, High x1.5, Critical x2) and internet exposure (from the collected facts, or set; internet-facing x1.5). A finding's risk score is its impact weight times both. Runs snapshot them when they start.",
    why: "Ranks the same weak cipher higher on a critical, internet-facing system than on an internal test box.",
    example: "High finding (7) on a Critical, internet-facing source: 7 x 2 x 1.5 = 21.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, grade inputs (components/cbom/sources/GradeInputsCard.tsx)
  // src: frontend/components/cbom/sources/GradeInputsCard.tsx:3-4, frontend/components/cbom/sources/GradeInputsCard.tsx:29-70 — Mosca X/Y/Z, per-source data lifetime, Q0 gaps; recorded at Start
  "cbsrc.rr.grade_inputs": {
    what: "What the next run's quantum risk grades use, recorded when you start it: the team's Mosca X, Y and Z, each source's own data lifetime (its X), and the evidence Q0 gaps. Later changes apply to new runs only.",
    why: "Without X, Y and Z, quantum-vulnerable assets grade as Unknown, and the record lets an old run's grade be explained later.",
    example: "X 10, Y 3, Z 12; Core banking DB keeps data 25 y; 2 Q0 gaps.",
  },
} as const satisfies TipAreaText;

export default TEXT;

/**
 * (i) tip text of the "scan" area (ids: scan.*, repo.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── shared by the scan list pages (routers/scans.py)
  // src: backend/utilities/db/schemas.py:8-9, backend/routers/scans.py:156-161 — title 1-256 characters; creating stores a NOT_STARTED scan, no credits
  "scan.new.title": {
    what: "A name for the new scan, 1 to 256 characters, shown in the scan list. Creating the scan uses no credits: you choose what to scan, see the credit estimate and start it on the next page.",
    why: "A clear title is how your team finds this scan again among dozens in the list and in reports.",
    example: "payments-api main, November release.",
  },
  // src: backend/utilities/db/schemas.py:46-47, backend/routers/scans.py:815-845 — rename sets only the title (max 256)
  "scan.rename.title": {
    what: "The new name of this scan, up to 256 characters. Only the label changes: results, findings and credits stay as they are.",
    why: "Renaming keeps lists and reports readable without rerunning or losing anything.",
    example: "payments-api before the PCI audit.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1259 — case-insensitive match on the title, in the loaded list
  "scan.filter.search": {
    what: "Shows only the scans whose title contains this text (upper or lower case does not matter). It filters the list already loaded in this page.",
    why: "Finds one scan quickly in a long list without scrolling.",
    example: "Typing \"api\" keeps \"payments-API main\" and \"api-gateway\".",
  },
  // src: backend/new_models.py:131, backend/routers/scans.py:599-610, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — the scan states and the refunds
  "scan.status": {
    what: "Not started: created, never run. Pending: queued for a scan worker. Started: running (the bar shows progress). Retry: the worker is retrying it. Success: finished, findings stored. Failure: stopped with an error; its credits were refunded. Cancelled: stopped by a user; its credits were refunded.",
    why: "The status tells you whether results exist yet and whether the credits were kept or refunded.",
    example: "A scan stuck in Pending is waiting for a free worker; it moves to Started when one picks it up.",
  },
  // src: backend/new_models.py:132, frontend/utils/datetime.ts:6-7 — stored in UTC; the text names no time zone because an IST browser reads the API's offset-less UTC time as local time until #48 is fixed
  "scan.table.created": {
    what: "When the scan was created: the date and time it was added to this list, before it was started.",
    why: "Results reflect the code as it was when the scan ran, so the date tells you how current they are.",
    example: "9 Aug 2026, 07:30 pm.",
  },
  // src: backend/utilities/celery/celery_connection.py:182, backend/utilities/celery/celery_connection.py:200-215, frontend/utils/datetime.ts:6-7 — today's behaviour: set on every status poll of a pending or started scan (also without a change) and on every chat message; #47 narrows it to real changes
  "scan.table.updated": {
    what: "The last time the platform touched this scan: a status or progress change, a status check while it is queued or running (the list checks those each time it loads), or a chat message about its results.",
    why: "Shows which scans are still moving and which have been quiet for a while.",
    example: "A scan queued since yesterday shows today's time once anyone opens the list today.",
  },
  // src: backend/routers/scans.py:475-486, backend/new_models.py:123, backend/utilities/db/scan_list_item.py:72, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — credit_consumed is the estimate (set by /estimate before any charge; credit_charged is separate), charged at start, refunded on failure or cancel
  "scan.table.credits": {
    what: "The scan's credit estimate. It is charged when the scan starts and refunded if the scan fails or is cancelled. A scan that was only estimated, and never started, has not been charged.",
    why: "Lets you see what each scan cost against the team balance.",
    example: "12.4 on a finished scan: 12.4 credits left the balance when it started.",
  },
  // src: backend/routers/scans.py:156-159, backend/utilities/db/scan_list_item.py:73-74 — owner_user_id is the user who created the scan
  "scan.table.owner": {
    what: "The team member who created the scan.",
    why: "Tells you whom to ask about a scan's setup or results.",
    example: "Priya Shah, priya@acme.com.",
  },
  // src: backend/routers/scans.py:634-651, backend/routers/scans.py:488-493, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — start re-estimates; a changed price answers 409 estimate_changed and charges nothing; failure and cancel refund
  "scan.cfg.run": {
    what: "Starts the scan and charges the estimated credits. The start prices the scan again first: if the price changed (another file, repository, branch or option), nothing is charged and you see the new price; press Start scan again to accept it. Failed and cancelled scans are refunded.",
    why: "Credits leave the balance at this point, so the price is checked again first.",
    example: "Estimate 3.2 credits, press Start scan: 3.2 credits leave the team balance.",
  },

  // ────────────────────────────────────────────────────────────── repository source (components/repository-card.tsx)
  // src: RabbitMQ/worker/helpers/context/scan_context.py:162-173, RabbitMQ/worker/helpers/context/git_hosts.py:8-14 — a zip or a clone of GitHub/GitLab/Bitbucket
  "repo.source": {
    what: "Where the code comes from: a .zip you upload, or a repository on GitHub, GitLab or Bitbucket that the scan worker clones. Use one of them.",
    why: "The scanner can only analyse code it can reach, so choose where it should fetch it from.",
    example: "Upload payments-api.zip, or connect https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/scan/format_input.py:44-52, RabbitMQ/worker/helpers/context/scan_context.py:175-216, backend/utilities/scan/credit_estimate.py:8-10 — upload capped at 50 MB (413); unpacked at most 2 GB and 50,000 zip entries (folders count); the estimate is bound to the file's size and SHA-256
  "repo.zip": {
    what: "A .zip of your source code, scanned instead of a repository: at most 50 MB to upload, and it may unpack to at most 2 GB and 50,000 entries (files and folders). The credit estimate is for this exact file: a different file is priced again when the scan starts.",
    why: "Lets you scan code that is not in a hosted repository, within the upload limits.",
    example: "payments-api.zip made with \"git archive --format=zip -o payments-api.zip HEAD\".",
  },
  // src: RabbitMQ/worker/helpers/context/git_hosts.py:8-14, RabbitMQ/worker/helpers/context/scan_context.py:92-139 — https on github.com / gitlab.com / bitbucket.org (or sub-domains), or a host listed in GIT_ALLOWED_HOSTS
  "repo.url": {
    what: "The https address of the repository. GitHub, GitLab and Bitbucket (and their sub-domains) are accepted; a self-hosted Git server works only if your administrator listed it in GIT_ALLOWED_HOSTS.",
    why: "The worker clones exactly this address; a typo or unsupported host fails the scan.",
    example: "https://github.com/acme/payments-api.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:31-49, RabbitMQ/worker/helpers/context/scan_context.py:89 — clone of that branch; default main
  "repo.branch": {
    what: "The branch the scan worker clones and scans. Leave it empty to scan main.",
    why: "Findings describe only the branch scanned, so pick the one that ships.",
    example: "release/2026.11.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:91-108 — GitHub token optional; a value that looks like a URL is ignored
  "repo.pat.github": {
    what: "A personal access token that can read the repository. Optional for public repositories, required for private ones. It is used to clone; paste the token itself, not a URL.",
    why: "Without a token that can read it, a private repository cannot be cloned.",
    example: "A fine-grained token with read-only Contents access to acme/payments-api.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:110-139 — GitLab (user oauth2) and Bitbucket (user x-token-auth) require a token
  "repo.pat.required": {
    what: "A token that can read the repository; required for GitLab and Bitbucket. The scan worker uses it to clone the repository.",
    why: "GitLab and Bitbucket refuse to clone without it, so the scan would fail.",
    example: "A GitLab project access token with the read_repository scope.",
  },
  // src: backend/utilities/db/scan_list_item.py:39, RabbitMQ/worker/helpers/context/scan_context.py:89 — the branch from the scan's settings (main by default)
  "scan.table.branch": {
    what: "The branch that was cloned and scanned. Empty for zip uploads.",
    why: "Findings apply to this branch only.",
    example: "main.",
  },
  // src: backend/utilities/db/scan_list_item.py:95-117, backend/utilities/db/scan_list_item.py:384-417, frontend/app/[team_id]/iac/page.tsx:123-126,959, frontend/app/[team_id]/dast/page.tsx:115-118,870 — today's scale for IaC and DAST: weights 4/3/2/1 averaged over findings, 0 without findings (#35)
  "scan.table.risk": {
    what: "This scan's severity-weighted average on a 1 to 4 scale: Critical 4, High 3, Medium 2, Low 1, averaged over its findings. 0 when it found nothing or did not succeed.",
    why: "Lets you compare scans by overall severity.",
    example: "1 High and 1 Low finding: (3 + 1) / 2 = 2.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:118-125,818, frontend/app/[team_id]/iac/page.tsx:128-135,838, frontend/app/[team_id]/dast/page.tsx:120-127,766, frontend/app/[team_id]/ai_bom/page.tsx:114-121,719, frontend/app/[team_id]/llm/page.tsx:123-130,760, frontend/app/[team_id]/cbom/page.tsx:120-127,928 — tiers on the Risk score column; the column is 1-4 for SCA + SBOM, IaC and DAST today (#35), 0-10 for AI BOM, LLM and CBOM; a null score matches no tier
  "scan.filter.risk": {
    what: "Shows only scans whose Risk score is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Where this table's score runs from 1 to 4 (SCA + SBOM, IaC, DAST), every scored scan is in Low. A scan without a score (shown as a dash) is hidden by any tier.",
    why: "Focuses the list on the riskiest scans.",
    example: "On the LLM list, High keeps a scan scored 7.5 and hides one scored 9.2.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:699-712, frontend/app/[team_id]/iac/page.tsx:719-732, frontend/app/[team_id]/dast/page.tsx:637-650, frontend/app/[team_id]/ai_bom/page.tsx:601-614, frontend/app/[team_id]/llm/page.tsx:568-581, frontend/app/[team_id]/cbom/page.tsx:668-681,971 — sorts the loaded rows; missing values count as -1
  "scan.filter.sort": {
    what: "Orders the table by creation date, risk score or credits, high or low first. Scans with no value for the chosen column go last when sorting high first.",
    why: "Brings the scans you care about to the top.",
    example: "Credits (high first) puts the most expensive scan on top.",
  },
  // src: backend/utilities/db/scan_list_item.py:142-143 — repo_url, or zip upload (IaC; the same fields for CBOM and AI BOM)
  "scan.table.source": {
    what: "The repository that was scanned (its last path segment; hover for the full URL), or Zip file for an uploaded archive.",
    why: "Tells you which code the results belong to.",
    example: "infra-live for https://github.com/acme/infra-live.",
  },
  // src: frontend/app/[team_id]/mcp/page.tsx:712-716 — sorts the loaded rows by created_at
  "scan.filter.sort_created": {
    what: "Orders the table by creation date, newest or oldest first.",
    why: "Brings the newest or oldest scans to the top.",
    example: "Newest puts the scan you created last on top.",
  },
} as const satisfies TipAreaText;

export default TEXT;

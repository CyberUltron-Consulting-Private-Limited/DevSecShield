/**
 * (i) tip text of the "repos" area (ids: repos.*): the Repositories pages (F3: org import, inventory, connections,
 * scan policies, runs and queue, findings roll-up), loaded on demand by content/infotips/load.ts. The label of each
 * tip is in content/infotips/labels.ts; the rules for the text are in content/infotips/index.ts (checked by
 * content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── Repositories (F3): org import, inventory, policies, runs, roll-up
  // src: backend/utilities/scm/filters.py:9-11, backend/utilities/scm/filters.py:80-83 — shell globs on owner/name and the bare name, case-insensitive; exclusions win
  "repos.filters.include_names": {
    what: "Shell globs (*, ?, [ab]) matched without regard to case against owner/name and against the bare name. When the list is not empty, a repository must match one of them. Up to 100 entries of up to 200 characters. Empty: every repository.",
    why: "Keeps a large organisation to the repositories you mean to scan, so a bulk run is not priced and charged for the rest.",
    example: "payments-* keeps acme/payments-api and acme/payments-web.",
  },
  // src: backend/utilities/scm/filters.py:6-11, backend/utilities/scm/filters.py:80-81 — an excluded name is out even when an include pattern matches it
  "repos.filters.exclude_names": {
    what: "Shell globs on owner/name or the bare name; a repository matching one is out of scope even when it also matches an include pattern. The inventory shows it as excluded by name.",
    why: "Drops sandboxes and archives that match a broad include rule, so they are never scanned or charged.",
    example: "*-sandbox keeps acme/payments-api but drops acme/payments-sandbox.",
  },
  // src: backend/utilities/scm/filters.py:71, backend/utilities/scm/filters.py:86-87 — at least one of the topics, case-insensitive
  "repos.filters.topics_any": {
    what: "Topics as GitHub and GitLab report them, compared without regard to case. When the list is not empty, a repository needs at least one of them. Bitbucket reports no topics, so this list leaves every Bitbucket repository out.",
    why: "Topics often mark what is in production or in an audit scope, which is what a compliance scan should cover.",
    example: "pci, production keeps a repository tagged pci.",
  },
  // src: backend/utilities/scm/filters.py:84-85 — any listed topic puts the repository out of scope
  "repos.filters.exclude_topics": {
    what: "A repository with any of these topics is out of scope (compared without regard to case), whatever the other rules say, except a manual include.",
    why: "Lets owners take a repository out of scans themselves by tagging it, without editing the filters here.",
    example: "deprecated drops every repository tagged deprecated.",
  },
  // src: backend/utilities/scm/filters.py:88-89 — the provider's primary language, case-insensitive
  "repos.filters.languages": {
    what: "The primary language the provider reports for each repository, compared without regard to case. When the list is not empty, other languages and repositories with no reported language are out of scope; GitLab reports no language, so its projects are left out.",
    why: "SAST reads only some languages, so limiting a SAST policy to them avoids queuing scans that would be skipped.",
    example: "Python, Java keeps a repository GitHub marks as Python.",
  },
  // src: backend/utilities/scm/filters.py:38, backend/utilities/scm/filters.py:78-79, backend/utilities/scm/pricing.py:1-15 — size as the provider reports it, in MB (0 to 1,000,000)
  "repos.filters.max_size": {
    what: "Repositories whose size, as the provider reports it, is above this many MB are out of scope. GitHub's size includes the git history. Empty means no limit; 0 to 1,000,000.",
    why: "Repository scans are priced from this size, so one very large repository can cost more than hundreds of small ones.",
    example: "500 leaves out a 2 GB monorepo.",
  },
  // src: backend/utilities/scm/filters.py:35, backend/utilities/scm/filters.py:72-73 — archived repositories are out unless this is ticked
  "repos.filters.include_archived": {
    what: "Ticked: archived repositories can be in scope. Not ticked (the default): every archived repository is out of scope, whatever the other rules say.",
    why: "Archived code no longer changes, so scanning it again usually spends credits without new information.",
    example: "Tick it once before an audit that needs every repository, archived ones too.",
  },
  // src: backend/utilities/scm/filters.py:36, backend/utilities/scm/filters.py:74-75 — forks are out unless this is ticked
  "repos.filters.include_forks": {
    what: "Ticked: forks can be in scope. Not ticked (the default): every fork is out of scope.",
    why: "A fork usually repeats its upstream's findings, which would be scanned and charged twice.",
    example: "Tick it when your team maintains patched forks of open-source libraries.",
  },
  // src: backend/utilities/scm/filters.py:37, backend/utilities/scm/filters.py:76-77 — none ticked: every visibility
  "repos.filters.visibility": {
    what: "Keep only repositories with a ticked visibility: private, internal (GitHub Enterprise and GitLab) or public. With none ticked, every visibility is kept.",
    why: "Public code is exposed to anyone, private code holds the internal systems: teams often scan one before the other.",
    example: "Tick Private and Internal to leave public open-source repositories out.",
  },
  // src: backend/routers/scm.py:173-178, backend/routers/scm.py:197-198 — GitHub (App or token), GitLab (group token), Bitbucket (workspace token)
  "repos.connect.provider": {
    what: "Where the repositories live: GitHub (github.com or GitHub Enterprise Server), GitLab (gitlab.com or self-managed) or Bitbucket (bitbucket.org). It decides which ways to connect are offered below.",
    why: "The provider's API is what lists the repositories and its credential is what clones them for scans.",
    example: "GitHub for an organisation on github.com.",
  },
  // src: backend/routers/scm.py:197-199, backend/utilities/scm/providers/github.py:1-6 — App installation (1-hour ghs_ tokens), org or user token, GitLab group, Bitbucket workspace
  "repos.connect.scope": {
    what: "What the connection lists and with which credential: a GitHub App installation (it mints 1-hour tokens), a GitHub organisation or your own repositories with a token, a GitLab group (subgroups included) or a Bitbucket workspace.",
    why: "One connection imports a whole organisation, group or workspace, so repositories are never added one by one.",
    example: "GitHub App installation on the acme organisation.",
  },
  // src: backend/routers/scm.py:174, backend/routers/scm.py:245 — 1 to 64 letters, digits, spaces, dots, dashes or underscores; unique in the team (409)
  "repos.connect.name": {
    what: "How this connection is shown in the inventory and the runs: 1 to 64 characters, starting with a letter or digit, then letters, digits, spaces, dots, dashes or underscores. Two connections of a team cannot share a name.",
    why: "With several organisations connected, the name is how you tell their repositories apart.",
    example: "Acme GitHub.",
  },
  // src: backend/routers/scm.py:178-179, backend/utilities/scm/providers/github.py:1-6 — the organisation, group path or workspace the connection lists
  "repos.connect.scope_name": {
    what: "The organisation (GitHub), group path (GitLab, e.g. bank/platform) or workspace (Bitbucket) whose repositories are listed, up to 255 characters. For a GitHub App installation it is only shown: the installation decides what is listed.",
    why: "A wrong name lists nothing or the wrong repositories; Test and the first discovery show the result.",
    example: "acme.",
  },
  // src: backend/utilities/scm/providers/github.py:1-6, backend/utilities/scm/providers/github.py:88-93 — the App id signs the JWT that mints installation tokens
  "repos.connect.app_id": {
    what: "The numeric id of your GitHub App, on the App's settings page. ZeroShield signs a short JWT with the App's private key and this id to mint installation tokens.",
    why: "Without the right App id GitHub refuses the key, and no repository can be listed or cloned.",
    example: "123456.",
  },
  // src: backend/utilities/scm/providers/github.py:1-6, backend/utilities/scm/providers/github.py:88-93 — the installation lists its repositories and gives the clone token
  "repos.connect.installation_id": {
    what: "The id of the App's installation on your organisation, the number at the end of the installation's settings URL. The repositories the installation can read are the ones imported.",
    why: "Repository access is granted per installation, so this decides exactly which repositories ZeroShield can read.",
    example: "45678901 from github.com/organizations/acme/settings/installations/45678901.",
  },
  // src: backend/routers/scm.py:199, backend/utilities/scm/providers/github.py:1-6, backend/routers/scm.py:104-114 — stored encrypted, never returned; mints 1-hour installation tokens
  "repos.connect.private_key": {
    what: "The GitHub App's RSA private key (.pem). It is stored encrypted, never shown or returned again, and used only to mint 1-hour installation tokens for listing and cloning.",
    why: "The key can act as the App on every installation, so it is kept write-only: replacing it means pasting a new one.",
    example: "-----BEGIN RSA PRIVATE KEY----- … from Generate a private key on the App page.",
  },
  // src: backend/routers/scm.py:199, backend/routers/scm.py:104-114, backend/utilities/log_redaction.py:1-20 — stored encrypted, never returned, never written to a log
  "repos.connect.token": {
    what: "A token that can read the repositories: it lists them and clones them for scans. It is stored encrypted, never shown or returned again and never written to a log. Read access is enough.",
    why: "A token with write access would let anyone holding it change your code; a read-only token limits the damage.",
    example: "A fine-grained GitHub token with Contents: Read on the organisation.",
  },
  // src: backend/utilities/scm/hosts.py:1-10, backend/routers/scm.py:177 — empty: the provider's cloud API; a self-hosted host must be in GIT_ALLOWED_HOSTS
  "repos.connect.api_base": {
    what: "Empty for github.com, gitlab.com or bitbucket.org. For a self-hosted server, its API URL; the host must be in the operator's GIT_ALLOWED_HOSTS list (the same list that allows cloning), otherwise the connection is refused. Redirects are never followed.",
    why: "Credentials are only ever sent to a server the operator allowed, never to an address someone typed.",
    example: "https://ghe.example.com/api/v3.",
  },
  // src: backend/routers/scm.py:491-520, backend/utilities/scm/pricing.py:1-20 — the preview prices one scan of the kept repositories; importing charges nothing
  "repos.import.price_products": {
    what: "The products used to price one scan of the repositories the filters keep, from each repository's reported size: about 1 credit per 0.5 MB for CBOM (at least 1 credit), IaC, SAST and AI BOM, and a flat price for SCA + SBOM. Importing charges nothing.",
    why: "Shows what scanning this selection would cost before any policy or Scan now spends credits.",
    example: "CBOM for 192 repositories: about 1,742 credits.",
  },
  // src: backend/utilities/scm/webhooks.py:1-20 — a per-connection URL and secret, shown once; signed pushes queue the policy's scans
  "repos.import.webhook": {
    what: "This connection's own webhook URL and secret. Add them as an organisation, group or workspace webhook for push events. Requests whose signature does not match the secret are refused. The secret is shown only now; a new one can be generated later.",
    why: "Without the webhook, policies with scan on push never see a push, so only schedules and Scan now start scans.",
    example: "GitHub: Settings, Webhooks, Add webhook, paste the URL, content type application/json and the secret.",
  },
  // src: backend/routers/scm.py:265-286, backend/utilities/scm/inventory.py:1-11 — one card per connection with its last discovery and the admin actions
  "repos.connections.card": {
    what: "One organisation, group or workspace connection: its provider and API, its last discovery (repositories found, API calls and rate-limit waits), sync now, test, import filters, a new webhook secret, disable and delete. Deleting refunds its queued scans.",
    why: "A failed or partial discovery leaves the inventory out of date; this is where you see it and run it again.",
    example: "Acme GitHub · GitHub App installation: acme · 1,000 found in 10 pages.",
  },
  // src: backend/routers/scm.py:183, backend/routers/scm.py:193, backend/routers/scm.py:352-354 — 15 to 10,080 minutes, 360 by default
  "repos.edit.sync_interval": {
    what: "How often the connection lists its repositories again on its own, in minutes: 15 to 10,080 (one week); 360 (6 hours) by default. Sync now runs it at once. Listing uses API calls only; nothing is scanned or charged.",
    why: "New repositories enter the inventory, and policies that cover them, only when a discovery sees them.",
    example: "60 for an organisation that creates repositories every day.",
  },
  // src: backend/routers/scm.py:331-339, backend/routers/scm.py:104-114 — write-only; required again when the API URL or scope changes
  "repos.edit.token": {
    what: "A token that replaces the saved one. The saved token is never shown; leave this blank to keep it. It is required again when you change the API URL or the scope, so a token can never be pointed at another server or organisation by someone who cannot see it.",
    why: "Rotating an expiring or leaked token here keeps the connection, its inventory and its webhook as they are.",
    example: "Paste the new fine-grained token before the old one expires.",
  },
  // src: backend/routers/scm.py:331-339, backend/utilities/scm/providers/github.py:96-112 — write-only; required again when the API URL, organisation or App changes
  "repos.edit.private_key": {
    what: "A GitHub App private key (.pem) that replaces the saved one; tokens it minted earlier are not reused. The saved key is never shown; leave this blank to keep it. It is required again when the API URL, organisation, App id or installation id changes.",
    why: "Lets you rotate the App's key on GitHub and here without deleting the connection or changing its webhook.",
    example: "After Generate a private key on the App page, paste the new .pem and delete the old key on GitHub.",
  },
  // src: backend/routers/scm.py:554-602, backend/routers/scm.py:607-618 — the discovered repositories, 50 per page, with the reason each is in or out
  "repos.inventory.section": {
    what: "Every repository your connections discovered, with why it is in or out of scope, the policy that covers it and its last scans. Removed repositories (no longer listed by the provider) keep their history and are shown under Scope: Removed.",
    why: "The scope column is what bulk runs and policies act on, so it is the place to check before spending credits.",
    example: "192 in scope of 240 discovered.",
  },
  // src: backend/routers/scm.py:567-568 — contains match on owner/name, case-insensitive
  "repos.inventory.search": {
    what: "Shows the repositories whose owner/name contains this text, without regard to case. The search runs on the server over the whole inventory, not just this page.",
    why: "Finds one repository among thousands without paging.",
    example: "pay finds acme/payments-api and acme/paygate.",
  },
  // src: backend/routers/scm.py:557-558 — repositories of one connection
  "repos.inventory.connection": {
    what: "Shows only the repositories discovered through one connection.",
    why: "With several organisations connected, it narrows the list to the one you are working on.",
    example: "Acme GitLab.",
  },
  // src: backend/routers/scm.py:559-566 — in, out (not removed), all visible, removed
  "repos.inventory.scope": {
    what: "In scope: repositories policies and Scan now act on. Out of scope: left out by a filter or by hand. All visible: both. Removed: repositories the provider no longer lists (their scans stay).",
    why: "Checking what is out, and why, catches a filter that drops repositories you meant to scan.",
    example: "Out of scope shows the 27 archived repositories and forks.",
  },
  // src: backend/routers/scm.py:569-570, backend/routers/scm.py:595-603 — the provider's primary language; the counts cover the connection's discovered repositories, not the other filters
  "repos.inventory.language": {
    what: "Shows only repositories with this primary language, as the provider reports it. The number counts the discovered repositories (not removed) of the chosen connection, or of every connection; search, scope, reason and scanned do not change it.",
    why: "Useful before a SAST run: SAST skips repositories in languages it cannot read.",
    example: "Python (84).",
  },
  // src: backend/routers/scm.py:571-572, backend/utilities/scm/filters.py:6-7, backend/utilities/scm/filters.py:101-102 — the first rule that decided the scope
  "repos.inventory.reason": {
    what: "Shows only repositories with one scope reason: matched, included or excluded by hand, or the first filter rule that put it out (archived, fork, visibility, too large, name, topic, language), or removed.",
    why: "Tells you which rule to change when a repository is unexpectedly in or out.",
    example: "Too large (3).",
  },
  // src: backend/routers/scm.py:575-578 — last_scan_at set or not
  "repos.inventory.scanned": {
    what: "Never scanned: no repository scan has finished on it yet. Scanned: at least one has.",
    why: "Finds the repositories a new policy or schedule has not reached yet.",
    example: "Never scanned, then select them all and choose Scan now.",
  },
  // src: backend/routers/scm.py:625-628, backend/utilities/scm/policies.py:57-63 — a pinned policy wins over the selector order
  "repos.inventory.pin": {
    what: "Makes the chosen policy cover the selected repositories whatever its selector and order say (only an enabled policy counts). No pinned policy goes back to the first policy whose selector matches.",
    why: "Handles the exceptions without bending a policy's selector around them.",
    example: "Pin acme/core-ledger to PCI nightly although it has no pci topic.",
  },
  // src: backend/routers/scm.py:625-627 — up to 10,000 repositories per bulk action
  "repos.inventory.select": {
    what: "Selects repositories for the bulk actions: Scan now (priced before anything is charged), Include or Exclude by hand, Back to filters, and pin to a policy. The header box selects every repository on this page.",
    why: "Acts on many repositories at once, with the price shown before any scan starts.",
    example: "Tick 2 repositories, then Scan now with CBOM.",
  },
  // src: backend/utilities/scm/models.py:1-60, backend/utilities/scm/providers/bitbucket.py:25 — owner/name, connection, default branch, archived and fork marks
  "repos.inventory.col.repository": {
    what: "The repository's owner/name with a link to it on the provider, then its connection and default branch, and whether it is archived or a fork.",
    why: "Identifies exactly which repository a row and its scans belong to.",
    example: "acme/payments-api · Acme GitHub · main.",
  },
  // src: backend/utilities/scm/filters.py:88-89, backend/utilities/scm/providers/gitlab.py:6 — the provider's primary language
  "repos.inventory.col.language": {
    what: "The primary language the provider reports; Unknown when it reports none (GitLab never reports one).",
    why: "SAST needs a language it can read; repositories in other languages are skipped, not charged.",
    example: "TypeScript.",
  },
  // src: backend/utilities/scm/pricing.py:1-20 — the reported size prices the scans
  "repos.inventory.col.size": {
    what: "The repository's size as the provider reports it (GitHub's includes the git history). Repository scans are priced from it.",
    why: "Larger repositories cost more to scan; this is where a surprising price comes from.",
    example: "2.0 MB: about 4 credits for a CBOM scan.",
  },
  // src: backend/utilities/scm/filters.py:93-102, backend/utilities/scm/inventory.py:41-43 — in, out with the first rule's reason, or removed
  "repos.inventory.col.scope": {
    what: "In scope, Out (with the reason: the first filter rule that left it out, or Excluded by hand) or Removed (the provider no longer lists it).",
    why: "Only in-scope repositories are covered by policies and scheduled runs.",
    example: "Out · Archived.",
  },
  // src: backend/utilities/scm/policies.py:57-67 — pinned policy, else the first enabled policy (by order) whose selector matches
  "repos.inventory.col.policy": {
    what: "The policy that covers this repository: the one it is pinned to, otherwise the first enabled policy in order whose selector matches. It says pinned or by selector, and on push when the policy scans on push.",
    why: "Tells you which products, branch and schedule will scan this repository.",
    example: "PCI nightly · by selector · on push.",
  },
  // src: backend/utilities/scm/queue.py:35-36, backend/routers/scm.py:104-130 — the latest scan per product, with its findings
  "repos.inventory.col.last_scans": {
    what: "The latest repository scan per product, with its status and number of findings; each badge opens that scan's results page.",
    why: "Shows at a glance which products have looked at this repository and what they found.",
    example: "CBOM 12 · SCA + SBOM 3.",
  },
  // src: backend/routers/scm.py:664-666, backend/utilities/scm/policies.py:57-67 — the order policies are tried in (0 to 100,000; lower first)
  "repos.policy.position": {
    what: "Policies are tried from the lowest number up (0 to 100,000; equal numbers by age). A repository is covered by the first enabled policy whose selector matches it, unless it is pinned to another.",
    why: "Overlapping selectors are common; the order decides which policy scans a repository and how it is charged.",
    example: "100 for PCI nightly, 200 for Everything weekly.",
  },
  // src: backend/routers/scm.py:665, backend/routers/scm.py:736 — 1 to 64 characters, unique in the team
  "repos.policy.name": {
    what: "How the policy is shown in the inventory and the runs: 1 to 64 characters, starting with a letter or digit, then letters, digits, spaces, dots, dashes or underscores. Two policies of a team cannot share a name.",
    why: "The name is what tells people why a repository was scanned.",
    example: "PCI repositories nightly.",
  },
  // src: backend/routers/scm.py:668, backend/utilities/scm/filters.py:1-11 — the same rules as the import filters
  "repos.policy.selector": {
    what: "The rules that pick this policy's repositories among those in scope, with the same rules as the import filters. The preview below counts them and those already taken by earlier policies.",
    why: "A selector that is too broad charges scans for repositories another policy should cover.",
    example: "Topics: pci.",
  },
  // src: backend/routers/scm.py:669, backend/utilities/scm/queue.py:62-70 — at least one product; SAST skips unreadable languages
  "repos.policy.products": {
    what: "The products every run of this policy queues for each repository it covers: SAST, IaC, SCA + SBOM, CBOM and AI BOM. Each repository and product is one scan, priced and charged when the run starts. SAST skips repositories in languages it cannot read.",
    why: "Each product adds one charged scan per repository, so a run's price grows with every product ticked.",
    example: "CBOM and SCA + SBOM: 2 scans per repository.",
  },
  // src: backend/routers/scm.py:676-690, backend/utilities/scm/queue.py:62-70 — the IaC frameworks passed to the IaC scan
  "repos.policy.iac_modes": {
    what: "Which infrastructure-as-code formats the IaC scan of this policy reads: Terraform, Kubernetes, Helm, CloudFormation, Ansible, Pulumi and AWS CDK. None ticked: all of them.",
    why: "Limiting the frameworks keeps the findings to what the repositories really use.",
    example: "terraform and helm for a platform team.",
  },
  // src: backend/routers/scm.py:670, backend/utilities/scm/queue.py:180-190 — empty: each repository's default branch
  "repos.policy.branch": {
    what: "The branch every scan of this policy clones. Empty: each repository's default branch. Pushes to other branches are ignored by scan on push.",
    why: "Scanning the branch that ships tells you about the code in production, not work in progress.",
    example: "release.",
  },
  // src: backend/routers/scm.py:671, backend/utilities/scm/webhooks.py:13-20 — a signed push to the branch queues the products at push priority, charged once per commit
  "repos.policy.on_push": {
    what: "A signed push to this policy's branch of a covered repository queues the policy's products at the highest priority, charged once per commit (a redelivered push queues nothing). It needs the connection's webhook.",
    why: "Findings show up minutes after code changes, instead of at the next scheduled run.",
    example: "A push to main of acme/payments-api queues its CBOM scan.",
  },
  // src: backend/routers/scm.py:667, backend/utilities/scm/policies.py:57-60 — a disabled policy covers nothing and never fires
  "repos.policy.enabled": {
    what: "A disabled policy covers no repository (the next policy in order does), never fires its schedule and ignores pushes. Its settings are kept.",
    why: "Pauses a policy, for example during a code freeze, without losing it.",
    example: "Untick it for the year-end freeze, tick it again in January.",
  },
  // src: backend/utilities/scm/policies.py:76-83, backend/utilities/scm/policies.py:137-185 — off, daily, weekly or monthly; each slot fires once, skipped when unaffordable
  "repos.policy.schedule": {
    what: "How often the policy runs on its own: off, daily, weekly or monthly. Each slot fires once; its run is priced and charged like Scan now, and skipped (nothing charged) when the team has too few credits.",
    why: "A schedule keeps every covered repository scanned without anyone starting runs.",
    example: "Weekly on Sunday at 02:00 Asia/Kolkata.",
  },
  // src: backend/utilities/scm/policies.py:80, backend/utilities/scm/policies.py:85-92 — HH:MM in the policy's time zone
  "repos.policy.time": {
    what: "The time of day the schedule fires, 00:00 to 23:59, in the policy's time zone.",
    why: "Running at night keeps scans out of working hours on your SCM and on the shared scanners.",
    example: "02:00.",
  },
  // src: backend/utilities/scm/policies.py:81, backend/utilities/scm/policies.py:124-127 — weekday 0 (Monday) to 6 (Sunday)
  "repos.policy.weekday": {
    what: "The day of the week a weekly schedule fires, at the time above in the policy's time zone.",
    why: "Picks a quiet day for the weekly run.",
    example: "Sunday.",
  },
  // src: backend/utilities/scm/policies.py:82, backend/utilities/scm/policies.py:128-129 — 1 to 28, so every month has it
  "repos.policy.monthday": {
    what: "The day of the month a monthly schedule fires, 1 to 28 (so every month has it), at the time above.",
    why: "Lines the monthly run up with a reporting cycle.",
    example: "1 for the first of each month.",
  },
  // src: backend/utilities/scm/policies.py:83, backend/utilities/scm/policies.py:94-98, backend/utilities/scm/policies.py:120-133 — an IANA zone; daylight saving follows it
  "repos.policy.timezone": {
    what: "The IANA time zone the time and day are read in; daylight saving changes follow it. An unknown name is refused when you save.",
    why: "02:00 means 02:00 where your team is, not in UTC.",
    example: "Asia/Kolkata.",
  },
  // src: backend/routers/scm.py:720-760, backend/utilities/scm/policies.py:57-67 — tried in order, first match covers
  "repos.policy.section": {
    what: "Which products scan which repositories, on which branch, on a schedule and or on push. Policies are tried in order and the first one whose selector matches covers a repository. Every run, scheduled or pushed, is priced and charged when it starts.",
    why: "Policies are how thousands of repositories stay scanned without starting runs by hand.",
    example: "PCI nightly (order 100) covers pci repositories; Everything weekly (order 200) the rest.",
  },
  // src: backend/routers/scm.py:833-881, backend/utilities/scm/queue.py:1-12 — priced first; charged once when the run starts
  "repos.run.products": {
    what: "The products to scan the selected repositories with now. Each repository and product is one scan; the price below is worked out first and the whole run is charged once when you start it. SAST skips repositories in languages it cannot read.",
    why: "Every product ticked adds one charged scan per repository.",
    example: "CBOM on 2 repositories: 2 scans.",
  },
  // src: backend/routers/scm.py:940-960, backend/utilities/scm/models.py:143-170 — one row per repository and product
  "repos.runs.col.repository": {
    what: "The repository this scan is for, with the branch it clones.",
    why: "Ties each scan of a run to its repository.",
    example: "acme/payments-api · main.",
  },
  // src: backend/utilities/scm/queue.py:62-70 — sast, iac, sbom_sca, cbom or ai_bom
  "repos.runs.col.product": {
    what: "Which product scans the repository: SAST, IaC, SCA + SBOM, CBOM or AI BOM.",
    why: "Results appear on that product's scan list and results page.",
    example: "CBOM.",
  },
  // src: backend/utilities/scm/queue.py:1-37 — waiting, sending, running, done, failed, skipped or cancelled
  "repos.runs.col.status": {
    what: "Waiting in the queue, Starting (being sent to a scanner), Running, Done, Failed, Skipped (for example the repository is gone; refunded) or Cancelled (refunded). Once a scan exists the status links to its results page; a failure shows the reason.",
    why: "Shows which scans of a run finished and which were given back.",
    example: "Failed · The scan could not be sent (refunded).",
  },
  // src: backend/utilities/scm/queue.py:1-19, backend/utilities/scm/queue.py:678-700 — the price charged; refunded once on failure, cancel or skip
  "repos.runs.col.credits": {
    what: "What this scan was charged when its run started. A scan that failed, was cancelled or was skipped is refunded once, and the row says refunded.",
    why: "Lets you check every credit a run took and gave back.",
    example: "4.00 (refunded).",
  },
  // src: backend/utilities/scm/queue.py:773-790, backend/utilities/scm/queue.py:22 — queued requests by trigger
  "repos.runs.waiting": {
    what: "This team's repository scans in the queue, not sent to a scanner yet, with how many came from pushes, from Scan now and from schedules. Waiting scans are already charged; cancelling a run refunds them.",
    why: "A long queue means results will take a while; push scans go first.",
    example: "40 · Scheduled 38 · Push 2.",
  },
  // src: backend/utilities/scm/queue.py:23-29, backend/utilities/scm/queue.py:74-91 — at most REPO_SCAN_MAX_INFLIGHT (8) across teams, half of them per team by default; lost scans are stopped and refunded
  "repos.runs.running": {
    what: "This team's repository scans being sent or running now. At most 8 run at once across all teams by default, and one team at most half of them; free slots go to the team with the fewest running. A scan no worker picks up within an hour, or that runs over 3 hours, is stopped and refunded.",
    why: "Explains why a big run takes time: scans run a few at a time, fairly shared.",
    example: "4 · up to 8 at once.",
  },
  // src: backend/utilities/scm/queue.py:35-36 — finished successfully
  "repos.runs.done": {
    what: "This team's repository scans that finished successfully; their results are on each product's scan list and in the findings roll-up.",
    why: "Shows how much of the queue has been worked through.",
    example: "1,020.",
  },
  // src: backend/utilities/scm/queue.py:1-19 — failed or skipped scans are refunded once
  "repos.runs.failed": {
    what: "This team's repository scans that failed or were skipped (repository gone, connection disabled, language SAST cannot read). Each was refunded once; the run's rows say why.",
    why: "A rise here usually means a credential or a connection needs attention.",
    example: "3 skipped: their repositories were deleted on GitHub.",
  },
  // src: backend/routers/scm.py:907-937, backend/utilities/scm/queue.py:22-29 — recent runs, newest first; push, then manual, then schedule
  "repos.runs.section": {
    what: "Each bulk run, push and schedule firing with its scans, credits charged and refunded. Cancel gives back what has not started; a scan already running can be cancelled on its own page.",
    why: "This is where you follow a large run and see what it cost.",
    example: "Run 12 · manual · 50 scans · 120 credits, 8 refunded.",
  },
  // src: backend/routers/scm.py:1028-1056 — in-scope repositories with at least one finished scan
  "repos.findings.scanned": {
    what: "In-scope repositories with at least one finished repository scan, out of all in-scope repositories.",
    why: "The roll-up only knows about repositories that have been scanned.",
    example: "180 / 192.",
  },
  // src: backend/utilities/scm/rollup.py:1-15, backend/routers/scm.py:1036-1046 — one finding per issue, not resolved
  "repos.findings.open": {
    what: "Issues still present in at least one repository, each counted once however many repositories have it.",
    why: "This is the real size of the backlog: fixing one issue clears it everywhere it appears.",
    example: "96 open findings in 180 scanned repositories.",
  },
  // src: backend/utilities/scm/rollup.py:1-15, backend/routers/scm.py:1031-1033 — occurrences summed over findings
  "repos.findings.occurrences": {
    what: "How many times the findings appear, counted per repository, as the latest scan of each repository found them.",
    why: "Compared with the distinct count, it shows how much the same issue repeats across repositories.",
    example: "2,655.",
  },
  // src: backend/routers/scm.py:1044-1046 — occurrences per open finding
  "repos.findings.dedup": {
    what: "Occurrences per distinct open finding. SAST titles come from a language model and vary between repositories, so SAST de-duplicates less than packages or crypto findings.",
    why: "A high ratio means a few shared fixes (a library, a base template) clear many repositories at once.",
    example: "27.7× when 96 findings appear 2,655 times.",
  },
  // src: backend/utilities/scm/rollup.py:1-15, backend/routers/scm.py:966-987 — most widespread first; a rescan replaces that repository's occurrences
  "repos.findings.section": {
    what: "One row per issue with the number of repositories it is in, most widespread first. A rescan of a repository replaces what it found there; a finding left in no repository is resolved and leaves this list.",
    why: "Shows which fixes remove the most risk across the organisation.",
    example: "lodash@4.17.15, CVE-2020-8203, in 41 repositories.",
  },
  // src: backend/routers/scm.py:979-980 — contains match on the title, case-insensitive
  "repos.findings.search": {
    what: "Shows the findings whose title contains this text, without regard to case; it searches every finding, not just this page.",
    why: "Finds one issue, a CVE or a package, among hundreds.",
    example: "lodash.",
  },
  // src: backend/routers/scm.py:975-976 — one product's findings
  "repos.findings.product": {
    what: "Shows only one product's findings: SAST, IaC, SCA + SBOM, CBOM or AI BOM.",
    why: "Each product's findings go to a different team, so each can see its own.",
    example: "CBOM.",
  },
  // src: backend/routers/scm.py:977-978, backend/utilities/scm/rollup.py:30 — critical, high, medium, low, info
  "repos.findings.severity": {
    what: "Shows only findings of one severity: critical, high, medium, low or info, as the scan reported it.",
    why: "Start with what is most likely to be exploited.",
    example: "Critical.",
  },
  // src: backend/utilities/scm/rollup.py:1-10 — the issue, identified without its location
  "repos.findings.col.finding": {
    what: "The issue, identified without its location: a package and its CVEs, a rule title, a crypto asset with its finding codes, or an AI component. Click it for every repository and place it appears.",
    why: "The same issue in many repositories is one row, so it is fixed once.",
    example: "Prototype pollution in lodash@4.17.15.",
  },
  // src: backend/utilities/scm/rollup.py:1-10 — the product whose scans found it
  "repos.findings.col.product": {
    what: "The product whose repository scans found it.",
    why: "Tells you which results page has the details and who usually owns the fix.",
    example: "SCA + SBOM.",
  },
  // src: backend/utilities/scm/rollup.py:30, backend/routers/scm.py:982-985 — the scan's severity
  "repos.findings.col.severity": {
    what: "The severity the scan reported for this issue.",
    why: "Severity and spread together say what to fix first.",
    example: "High.",
  },
  // src: backend/routers/scm.py:980-985, backend/utilities/scm/rollup.py:11-15 — repositories where it is present now
  "repos.findings.col.repositories": {
    what: "In how many repositories the issue is present, as their latest scans found it.",
    why: "The more repositories, the more one shared fix is worth.",
    example: "41 of the 180 scanned repositories.",
  },
  // src: backend/routers/scm.py:982-985, backend/routers/scm.py:1016 — occurrences counted per repository and location
  "repos.findings.col.places": {
    what: "How many times the issue appears in all those repositories together; one repository can have it in several files.",
    why: "Shows the effort of the fix where it cannot be made in one shared place.",
    example: "63 places in 41 repositories.",
  },
} as const satisfies TipAreaText;

export default TEXT;

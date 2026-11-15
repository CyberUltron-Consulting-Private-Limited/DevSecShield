/**
 * (i) tip text of the "settings" area (ids: settings.*, account.*, admin.*, ticketing.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── Team settings (app/[team_id]/settings/page.tsx)
  // src: backend/routers/team.py:86, backend/utilities/team/invitations.py:219, backend/routers/team.py:173 — creator is admin, invitees join as member
  "settings.members": {
    what: "Everyone in this team and their role. Admin: the team's creator (and other admins) can edit the team, invite, remove members and delete it. Member: runs scans and works on findings. Tick members to remove them.",
    why: "Roles decide who can change settings, credentials and team data.",
    example: "you@acme.com admin, dev@acme.com member.",
  },
  // src: backend/utilities/team/invitations.py:1-9, backend/utilities/team/invitations.py:33 — single-use link, 7 days, no password mailed
  "settings.invite": {
    what: "Mails the address a single-use invitation link, valid for 7 days. No password is sent: a new person chooses one on the invitation page, an existing user signs in and accepts. Nobody joins until they accept.",
    why: "Only invited people can see the team's scans and findings.",
    example: "dev@acme.com joins as a member after clicking the link.",
  },
  // src: backend/utilities/team/invitations.py:1-9, backend/utilities/team/invitations.py:33, backend/routers/team.py:466-490 — open invitations; resend replaces the link; revoke cancels it
  "settings.invitations": {
    what: "Invitations not yet accepted, with their status and expiry (7 days after sending). Resend mails a new link (the old one stops working); Revoke cancels it.",
    why: "Expired or unaccepted invitations may need resending or revoking.",
    example: "dev@acme.com · pending · expires 18 Nov.",
  },
  // src: backend/utilities/db/schemas.py:24-37, backend/utilities/integrations/jira.py:111-208 — Jira Cloud REST v3 with email + API token
  "settings.jira": {
    what: "Connects the team to Jira (REST API v3, as used by Jira Cloud) so scans can create Jira issues from findings. Each scan chooses its project and whether tickets are created automatically.",
    why: "Findings reach your team's normal work queue instead of staying in a dashboard.",
    example: "https://acme.atlassian.net with a bot account's API token.",
  },
  // src: backend/utilities/integrations/jira.py:111-121 — basic auth email + token
  "settings.jira.email": {
    what: "The email of the Jira account the tickets are created as. It needs access to the projects you will pick.",
    why: "Tickets are created as this account, so it needs access to the projects.",
    example: "security-bot@acme.com.",
  },
  // src: backend/utilities/db/schemas.py:27, backend/utilities/integrations/jira.py:118 — the site URL; REST paths are added to it
  "settings.jira.url": {
    what: "The address of your Jira site, without a path.",
    why: "Tickets are created on this site only.",
    example: "https://acme.atlassian.net.",
  },
  // src: backend/utilities/db/schemas.py:26, backend/utilities/integrations/jira.py:111-121 — secret field, never printed; basic auth with the email
  "settings.jira.token": {
    what: "An API token of that Jira account (Atlassian account settings > Security > API tokens). It is stored for the team and never printed in logs.",
    why: "Without a valid token no ticket can be created.",
    example: "A token created for the security-bot account.",
  },
  // src: backend/utilities/db/schemas.py:20-22, backend/routers/team.py:193-215 — admin only
  "settings.team.name": {
    what: "The team's name, shown in the team switcher. Only admins can change it.",
    why: "Helps members find the right team in the switcher.",
    example: "Payments platform.",
  },
  // src: backend/utilities/db/schemas.py:20-22, backend/routers/team.py:193-215 — optional text
  "settings.team.description": {
    what: "An optional note about what this team covers.",
    why: "Tells members what the team covers.",
    example: "Scans for the payments services and their infrastructure.",
  },
  // src: backend/routers/team.py:297-330 — admin only; the default team cannot be deleted; scans and CBOM Sources data are deleted
  "settings.danger": {
    what: "Deleting the team removes its scans, findings and CBOM Sources data for everyone. Only admins can do it, and your default team cannot be deleted.",
    why: "Deletion cannot be undone and affects every member.",
    example: "Delete a team created for a finished project.",
  },

  // ────────────────────────────────────────────────────────────── Per-scan ticketing (components/ticketing-integrations-settings.tsx)
  // src: backend/utilities/db/schemas.py:39-45, backend/utilities/integrations/jira.py:196 — project used for issues created from this scan
  "ticketing.jira_project": {
    what: "The Jira project where tickets for this scan's findings are created, using the Jira connection in team Settings.",
    why: "Tickets land in this project, so pick the one the owners work in.",
    example: "10001 (the numeric id of project SEC).",
  },
  // src: backend/utilities/db/schemas.py:39-41, backend/utilities/celery/celery_connection.py:236-239, backend/utilities/integrations/jira_ticketing.py:20, backend/utilities/integrations/jira_ticketing.py:199-242 — one task per finding when the scan succeeds, cap 50
  "ticketing.auto_create": {
    what: "When on, one Jira task is created per finding as soon as this scan succeeds (at most 50 per scan). Marking a finding Fixed closes its ticket.",
    why: "Every finding becomes a tracked task without manual work.",
    example: "Turn it on for a nightly scan your team triages in Jira.",
  },

  // ────────────────────────────────────────────────────────────── Account (app/[team_id]/account/page.tsx)
  // src: backend/routers/auth.py:351-363 — the current password is checked before the change
  "account.current_password": {
    what: "Your present password, to prove it is you before the change.",
    why: "Stops someone at an unlocked screen from changing your password.",
    example: "The password you signed in with today.",
  },
  // src: backend/utilities/auth/auth_utils.py:203-243, frontend/utils/password_rules.ts:1-8 — 8 to 128 characters, at most 512 bytes
  "account.new_password": {
    what: "8 to 128 characters (an emoji counts as one), at most 512 bytes. After the change every other browser and device is signed out; this one stays signed in.",
    why: "A strong, unique password protects access to your team's findings.",
    example: "A passphrase such as \"correct-horse-battery-staple\".",
  },
  // src: frontend/app/[team_id]/account/page.tsx:56-68,123 — must equal the new password
  "account.confirm_password": {
    what: "Type the new password once more, so a typo does not lock you out.",
    why: "Prevents a typo from locking you out.",
    example: "The same passphrase as above.",
  },
  // src: backend/routers/auth.py:1-8 — logout revokes every token issued before it
  "account.sessions": {
    what: "Sign out everywhere ends every session of your account, on every browser and device, this one included.",
    why: "Ends access from a lost or shared device.",
    example: "Use it after signing in on a shared computer.",
  },

  // ────────────────────────────────────────────────────────────── Admin (app/admin/page.tsx, superusers only)
  // src: backend/routers/admin.py:200-262 — superuser account; temporary password; a single-use choose-your-password link is mailed
  "admin.create_user": {
    what: "Creates a superuser account. The password you set is temporary: the user must choose their own at first sign-in, and is mailed a single-use link to do it (the password itself is never mailed).",
    why: "Admins can see and change every team, so create them sparingly.",
    example: "ops@zeroshield.example with a temporary password.",
  },
  // src: backend/routers/admin.py:220-235 — one account per email
  "admin.email": {
    what: "The new admin's sign-in email. It must not belong to an existing account.",
    why: "The new admin signs in with it.",
    example: "ops@zeroshield.example.",
  },
  // src: backend/routers/admin.py:219-222, backend/utilities/auth/auth_utils.py:203-243 — temporary; 8-128 characters
  "admin.password": {
    what: "A temporary password, 8 to 128 characters; the user replaces it at first sign-in.",
    why: "A temporary password limits the damage if it is shared insecurely.",
    example: "A random 16-character string.",
  },
  // src: backend/routers/admin.py:236-246 — stored on the account
  "admin.name": {
    what: "The new admin's first and last name, shown in team member lists and scan owners.",
    why: "Shows who the admin is in member lists and scan owners.",
    example: "Asha Rao.",
  },
  // src: backend/routers/admin.py:153-199, backend/routers/admin.py:355-424 — every user, teams, superuser switch
  "admin.users": {
    what: "Every account on this installation, its teams and whether it has admin (superuser) access. The switch grants or removes that access.",
    why: "Lets you review who has access, and who has admin rights.",
    example: "Turn off Admin Access for someone who changed role.",
  },
  // src: backend/routers/admin.py:97-152, backend/routers/admin.py:291-354 — every team; the credit balance is set (not added), never negative
  "admin.teams": {
    what: "Every team with its members, credit balance and scan count. Editing the balance sets it to the number you enter (it does not add to it); it cannot be negative.",
    why: "Lets you check usage and set credit balances.",
    example: "Set 5000 to give a team 5,000 credits in total.",
  },
} as const satisfies TipAreaText;

export default TEXT;

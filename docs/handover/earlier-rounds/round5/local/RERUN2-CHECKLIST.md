# Regression 2 checklist (Nov 11) — browser only, as a customer, on the rebuilt stack

Invitation and set-password links in mail point at CBOM_PUBLIC_APP_URL; if that is the production host, replace the
host with https://devsec.dss.test and keep the path/token (a customer's mail would carry the right host).

## Cancel scans (C1)
1. SAST (zip), IaC (zip), CBOM (zip), AI BOM (zip): start, then Cancel scan: dialog states the charge; "Keep scanning"
   and Escape close it; confirm -> toast, "Cancelled — N credits refunded", balance up by N, still after reload,
   Cancelled badge and filter in the list. (SCA+SBOM: dialog only, do not run the scan.)
2. Queued: stop dss-staging-scan-worker-1 (`docker stop`), start a CBOM zip scan, cancel, `docker start` the worker:
   scan stays cancelled, worker log shows it skipped. (Integrator allows this one platform action.)
3. Running: cancel a CBOM scan mid-run; within ~5 s no engine/tool process remains in scan-worker (`docker top`).
4. Second tab: cancel again -> no error toast. Completed/failed scan: no Cancel button.
5. Run again from a cancelled scan opens a prefilled new scan. Dashboards do not count cancelled as completed/failed.

## Fresh-customer fixes (X1) and polish (P1)
6. Double-click Create in New Scan (all 8 product pages) creates one scan; double-click Create node creates one node;
   two concurrent creates of the same node name -> second refused (409) with a clear message.
7. DAST: a refused estimate keeps every field; a failed DAST scan shows its real reason and Run again (prefilled,
   password asked again).
8. MCP: estimate against a 404/unreachable URL -> clear reason (not "try again later"); invalid header JSON -> field error.
9. "Try Again" on the other sidebars no longer reloads/wipes input.
10. Toasts: errors stay readable (~8 s or until dismissed), up to 3 visible; wording "SAST scan created", no toast on
    reads; server-source 400s show field labels, not "config.".
11. Phone (390x844): menu button opens navigation on team and home pages; it closes on navigation.
12. Account page from the user menu: change password (wrong current refused; rules enforced), other sessions signed out
    (second browser context gets signed out), Sign out everywhere works.
13. Icon-only buttons on LLM and scan pages have accessible names.

## Invitations and secrets (S2)
14. Admin invites a new address: mail has no password, names team and inviter, footer 2026; Pending list shows it.
15. Link -> create account with own password -> lands in the team; link reuse -> "not valid any more".
16. Invite an existing user: signed out -> "Sign in as …"; wrong account -> message; Accept; another invite -> Decline.
17. Resend kills the old link; Revoke works; removing a member asks for confirmation.
18. Member (non-admin): Jira fields read-only with the note; admin: token field empty with "saved"; saving with it
    empty keeps the token; changing the Jira URL with it empty is refused.
19. Superuser creates an account (if the operator UI exists): mail has a set-password link, no password; first sign-in
    with the temporary password asks for a new one.

## Sources counted as results (M1x)
20. Team with a Sources run: CBOM dashboard counts its assets, top risks show the Source column; Table tab lists the
    run; team home counts it; all deliverables enabled; Network TLS PDF lists the probed endpoint and does not say
    "does not probe any endpoint"; severity counts equal the run page's.
21. Team with only code scans: Network TLS PDF still says it probed no endpoint.

## DAST pinning (D1)
22. DAST estimate/start on refused targets still refused with reasons; with an allowed public target (if reachable)
    the scan metadata shows egress counts; nothing reaches internal addresses (dast-worker log).

## Proxy (nginx)
23. Through the stack's nginx: a WebSocket upgrade request to the frontend host gets 101 when the upstream supports it
    (or is passed through), and normal pages load.

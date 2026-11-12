# Final regression checklist on the rebuilt local stack (customer behaviour, UI only)

Collected from the agents' "re-run after rebuild" lists. Each line: what to do in the UI, and what must be true.
Evidence of the original runs: $S/local/u1, $S/local/u2, $S/local/u3, $S/local/g1, $S/local/g2, $S/ui/l1, $S/ui/u1, $S/ui/u2
(S=/tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/round5). Scripts in those folders may be reused.

## Scan nodes and Sources (U1, U3, G2, G3)
1. Add scan node: wizard opens in view; the Docker command uses per-node container/volume names (zs-node-<name>); two
   nodes on one host both register as themselves. "Cannot pull …?" section shows make node-image / sha256sum -c /
   docker load (Docker and Helm). Reset view shows the old name and a hint to remove the old container.
2. Servers: Tier 2 sudoers download is saved as "zs-cbom" (no .txt) and its own install line works on the target;
   Tier 2 test on a server without iproute2 does not say "sudoers missing"; editing a password source and changing
   pinned host keys without re-typing the password shows "Enter it again: …" in the form (not a 1.5 s toast);
   AD (LDAPS) CA hint does not mention WinRM; Edit from the table scrolls to the form (Servers, K8s & DB).
3. Databases: MySQL 8 auto-generated ca.pem uploads as-is (trailing NUL) and the source saves; PostgreSQL grant SQL
   says RDS users skip the pg_hba_file_rules lines.
4. Debian target with an expired RSA-1024 server certificate in /etc/ssl/certs: a certificate finding and a calendar
   entry; the trust-store row counts only CA certificates.
5. Review & Run: Kubernetes row with images only says "N container images"; HSM counted as HSM; with the team window
   closed, Servers/Databases/K8s rows say "Outside the scan window: starts …" and Estimate says when before Start;
   a refused Start (e.g. no credits) shows the server's message.
6. Network range (/29 with a few TLS targets, one silent address): finishes in well under a minute, asset count grows
   while running, the silent address gets a "no answer" coverage row; discovery sweep shows open endpoints only.
7. Drift: run twice, change one target between runs (swap a cert, enable TLS 1.0), stop one target: changed/new items
   correct; the stopped target is "not read", never "resolved".
8. Schedules: create daily/weekly, invalid input messages, pause/resume, delete; next-run time in the team's zone.
9. AWS form on this stack (no CBOM_AWS_PRINCIPAL_ARN): "This ZeroShield deployment is not set up for AWS
   collection; contact your administrator", no template; Validate says the same.
10. Node behaviour: Reset a node -> the agentless node's log says "server at … did not accept this node …" only for a
   non-explicit 401; a pool (agent) pod re-enrolls after a reset. Host finding text for /etc/nginx/nginx.conf names
   the line and says to use "ssl_protocols TLSv1.2 TLSv1.3;".
11. Remediation waves on a finished run's results.

## Code scans (U2, G1, G3)
12. Zip scan u2-cbom-full.zip with "Scan binaries" on: the git-history key and the firmware key are findings;
   coverage says raw binaries read; dialog width fits at 390 px and 1440 px; Quantum filter and column agree
   ("Broken today" option); import card; header wraps on a phone; export buttons on screen at 390 px.
13. CycloneDX 1.5 upload: the sidebar shows "No cryptographic assets were imported …" with the engine's notes right
   after the run; the PDF has the "About the uploaded CBOM file" section.
14. Opening 15+ findings in a minute does not hit "Could not load the remediation"; the next Estimate is not 429.
15. Repository scan with a bad branch / missing repo: a 400 that says why (not "Internal server error").
16. SAST and IaC zip scans (no LLM here): the sidebar shows the real failure reason + "Create a new scan …".
17. Readiness gauge on a scan with MD5/DES equals the Quantum column; legend shows "Broken today"; PDF the same.
18. Signed out, /pqc-vuln-verify: sign-in page or 404, never fixture data.
19. Phone 390x844 code-scan page: chat full width with the sidebar below; menus say "Rename scan"/"Delete scan".
20. Start a scan whose stored estimate is out of date (or change options so the price changes): the new price is
   shown before any credit moves.
21. Library that reached end of life after its run: finding in list, totals, panel and CycloneDX ("Judged today …").
22. Mosca form: save; a conflicting save from another tab says "This was changed elsewhere. Reload…".

## Auth, settings, DAST, integrations (L1, G1)
23. Sign-in code mail failure shows the 503 message; Resend countdown runs; a 403 shows why and keeps the session.
24. DAST: manual estimate/start of http://169.254.169.254/…, http://backend:8080/, http://localhost/, 10.x and a
   name resolving to a private address are refused with a clear reason in the sidebar; a public or allowlisted
   target works; "Estimate credits" disabled state says why.
25. Integrations: saving an enabled integration with a loopback/metadata destination is refused at save with Test's
   message; a valid receiver still delivers.
26. A zip-mode upload that is not a zip gets a clear 400 for all five scan types.

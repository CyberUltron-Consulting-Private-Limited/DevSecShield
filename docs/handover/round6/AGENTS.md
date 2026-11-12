# Coordinator's agent registry (round 6 parallel tracks)
| Track | Role | Agent id | Branch / output | State |
|---|---|---|---|---|
| T0 #12-#15 | builder | aafcd843517dfe5bc | fix/r2-polish, PR #30 | done, in review |
| T0 | code/QA review | a00390d90026baed0 | PR #30 | approve, 3 minor |
| T0 | browser QA | a76783925546f6945 | PR #30 | running |
| T0 | security review | a01a1cad0be050695 | PR #30 | approve, 1 nit; filed #31 |
| T1 #17 | builder | ae54d435bf823c8a5 | fix/never-scan-dual-stack, PR #32 | CI running |
| T2 #33 credits | builder | a631dc0e4e9bcbeae | fix/reinitialize-credits | running |
| F1-ARCH | architect | a6f05f73d19f18721 | $R6/f1/CONTRACT.md | done |
| F1.1 | builder | abb1738ce914ee011 | feat/f1-node-api | running |
| F1.2 | builder | aa19ebccbae55b081 | feat/f1-inventory-scaffold, feat/f1-inventory | running |
| F1.3 | builder | a6b36a62aca3ba014 | feat/f1-zs-collect, feat/f1-transports | running |
| F1.4 | builder | a16064ba05e59a1fe | feat/f1-ssh-ca | running |
| F2 | builder | af47009b40c59c338 | feat/f2-info-tips | running |
| F3 | builder | a8c6feb6d649734df | feat/f3-repos-at-scale | running |
| F4 | builder | a88a0f0350db068a5 | feat/f4-rbac, -sso, -scim | running |
Done earlier: F0 builder a95e9bd14948e836f; release manager a68bbfa49c21ac46d.

## After the 12:14 UTC container restart (all builders relaunched; 20-subagent concurrency limit)
| Track | Role | Agent id | Target | State |
|---|---|---|---|---|
| T0 | browser QA (resumed) | a76783925546f6945 | PR #30 | running |
| F2 | content review (resumed) | a1a78fe0327214b88 | PR #38 | running |
| F2 | UX + browser QA (resumed) | ab52098b49f49c150 | PR #38 | running |
| F1.1 | security review (resumed) | aeab8ed8236286b83 | PR #41 @344d908 | running |
| F1.1 | arch/perf review (resumed) | a84a34df133526c53 | PR #41 @344d908 | running |
| F1.2 | security re-check (resumed) | a8ea781ba54683b7a | PR #34 @c4f6f57 | running |
| T1 | code/QA re-check | a268881f3eed9c28b | PR #32 | idle; resume when T1 pushes |
| F1.1 | builder | a884eb059ff54808b | PR #41, EC2 i-0c69a7da3e4b747a3 | running |
| T1 | builder | ae04e8d77e979ebfa | PR #32 fixes | running |
| T2 | builder | a945130350c0e67a2 | fix/reinitialize-credits | running |
| F1.2 | builder | a722852f1ad78f8a5 | feat/f1-inventory | running |
| F1.3 | builder | a9471ea17f3b7e5ac | feat/f1-zs-collect | running |
| F1.4 | builder | ac0e30802446bc0a7 | feat/f1-ssh-ca | running |
| F2 | builder | a7cd09bdba971cd8c | feat/f2-info-tips-2 | running |
| F3 | builder | afc403cfb6a79fefe | PR #40 + UI | running |
| F4 | builder | ab821ac8721fc275d | feat/f4-sso (+ #42 fixes) | running |
| F3 | security review | ae6a886d7b0f20c35 | PR #40 @20c26a3 | running |
| F3 | code/QA review | aa655db58174d2230 | PR #40 | running |
| F3 | architecture review | a71ae8223141de7dc | PR #40 | running |
| F4 | security review | ae92f8486d0a49a19 | PR #42 @b2933fc | running |
| F4 | architecture/migration review | a96bf725c3cb91705 | PR #42 | running |
QUEUED (limit): browser QA of PR #42 role matrix; T0 fixer for PR #30 (security nit, 3 code/QA minors, #31, QA defects).
| T0 | fixer | ac9c8bbb2c95948f8 | PR #30 review items + #31 | running |
| F2 | content review | a1a78fe0327214b88 | PR #38 | DONE: changes needed, review 5858670025; filed #45-#49 from it |
QUEUED (limit 20): browser QA of PR #42; T3a bug-fix builder (#45+#37 path patterns, #46 SBOM inventory, #47 last_updated, #49 zip source); T3b (#48 timestamps, #35, #36).

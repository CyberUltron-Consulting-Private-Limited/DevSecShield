# Next unowned CBOM issues — 2026-11-15

Worktree `DevSecShield-wt-next`, base `origin/dev` `15a06b0b` then company `dev`. Merged to `dev` only. Not promoted. A Deploy staging run was in progress (`43719311276`), so no promotion PR was opened. Not merged to `main`.

| Issue | What | PR | SHA | Tests or skip |
| --- | --- | --- | --- | --- |
| #407 | Already on `dev` (scan node names the z05b ML-DSA-65 signature and key through algid; quantum-safe). Duplicate #418 closed without merge. KF-3 stays pinned until a live Tier-L run. | https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/419 | merge `9cecdf749786a7046613e394bbe917bb5fbfe21a`, change `3640036d1d803b0d2f29d033cab17d0cb2ad7d95` | `scan_node/tests/test_certparse_mldsa.py` |
| #408 | Already on `dev` (CB-14 refunds runtime skips). Closed. Billing not rewritten. KF-8 stays NOT-RUN until CB-05 adds G10. | https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/308 | merge `9cfcd14132d78a894b926931b834b2b208ea4168`, change `ebf6859ddfbce58c8c340be6435767e16244c731` | `backend/tests/test_cbom_cb14_billing.py::test_r2_two_of_four_targets_skipped_by_the_window_refund_half` |
| #410 | Already on `dev` (CB-11 compares a range that contains a never-scan address). Closed. Never-scan not rewritten. KF-12 stays NOT-RUN until CB-05 runs G13b. | https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/290 | merge `6cd5f8e3ce38ba59059da14f638232d42fde3ac6`, change `f2e6d8239ba093c9066c2c2d3c07334ce287a9c0` | `backend/tests/test_cbom_cb11_never_scan.py::test_f1_a_never_scan_address_in_a_range_keeps_the_range_comparable_and_a_fix_resolves` |
| #411 | Already on `dev` (evidence older than 365 days is E0 with a Q0 gap; the export carries the gap snapshot). Closed. KF-14 stays NOT-RUN until CB-05 runs G8. | https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/143 and https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/162 | `af280e7b22a7f5e44853238edcb2722c674c5f2d` (CB-18), merge `ca22af52db11a6d9f666ec052dcc983e1c0c0d5e` (PR #162) | `backend/tests/test_cbom_cb18_evidence_confidence.py::test_expired_evidence_is_e0_with_its_reason_everywhere`; `backend/tests/test_cbom_cb19_grade_snapshot.py::test_export_names_the_snapshot_gaps_and_the_unread_scope` |

Left open on purpose:

- #409 KF-10. `unknown` is already a PQC class (`af280e7b`) and Q-grades are stored (`ca22af52`). The issue's remaining step is the posture oracle, which CB-05 owns (open PR #102, skipped).
- #389 live tracker.
- Skip list: #41 #42 #63 #99 #102 #126 #146 #118 #64, #397 #401 #403 #404 #399 #405 #47 #406 #68 #413, #73 #93, #83, #368 #369, #18 #39 #60, and the cloud/network bugs already on `dev`.
- Other open issues have an open PR (#12 #13 #14 #15 #28 #31 on #67, #33 on #57) or are not CBOM product bugs (#56, #86, #53, #45, and the CI follow-ups).

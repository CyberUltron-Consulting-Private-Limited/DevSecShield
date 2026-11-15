# CBOM live tracker

The live sheet the owner reads is GitHub issue
[#389](https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/issues/389).
Session C updates that issue. This file is a short pointer plus a copy of the
2026-11-15 17:54 IST sheet. It contains no credentials.

## Status (2026-11-15 17:54 IST)

Deploy staging for promotion #395 **succeeded**.
[Run 43711034711](https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/actions/runs/43711034711)
built and deployed staging SHA `71a95e3a800375c579aced628f6ee70aeae83d35`
(image tag `71a95e3a8003`). `staging.sh check` reports that tag up, API health
200, and the frontend login page 200. Recent Deploy staging runs: this one
success; [#391 run 43707991325](https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/actions/runs/43707991325)
failure; [run 43695859431](https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/actions/runs/43695859431)
success. No further deploy was started.

| Row | Status |
|---|---|
| R1–R6, R9–R11 | On staging (results template). Run URL is `/{team}/cbom/run-{id}/results` (example `/1/cbom/run-12/results`). `/1/cbom/2/results` is code scan 2, not Sources run 2. Legacy `/cbom/runs/{id}/results` redirects. |
| R7, R21 | Bedrock is ON on staging. `GET /1/cbom/ai/status` available true, provider bedrock, model `global.anthropic.claude-haiku-4-5-20251001-v1:0`, region `ap-south-1`. Fix mode returned outcome=ok in about 3s for a Cisco IOS SSH finding. Owner should still rotate the key that was pasted in chat. |
| R8 | Only egress is `bedrock-runtime.ap-south-1.amazonaws.com:443`. |
| C1–C10 | Verified FIXED live on staging by QA (issue comment 6893986957), including GCP false-pass refused with 0 credits, ADFS visible, Azure "Partly read · 11 read", deduped certs, unused API keys not stored, EJBCA mismatch refused at save, AD CS one status (host 172.31.35.52 still unreachable — owner must start it), KMS_NO_ROTATION, timeout/SAML/PQ profile labels. |
| N1, N3, N8, N11 | FIXED live on node 3 `staging-lab-node` 1.0.2+96e25631764b, run 38. SNI shop.lab and pay.lab read; .127 and .128 scanned; rate peak 19/s vs cap 20/s; F5 DEFAULT kept TLS 1.2; IOS dh min size 1024 and ASA dh-group group2 raised DH_LT_2048. Evidence comment 6894199487. |
| N2, N4–N7, N9, N10, N12 | Previously verified FIXED live. |
| Q1 / lab nodes | Node 3 is 1.0.2. HSM node `staging-hsm-node` was left on `cbom-lab/scan-node-hsm:1` on purpose (the 1.0.2 image has no libsofthsm2; tokens live in that image). Source 50 (upper /25) was moved to node 3 for the retest. |
| #393 / #395 | `CBOM_CT_DISCOVERY` is wired like the AI provider. Deploy run 43711034711 succeeded. Staging is on `71a95e3a8003`. |
| #394 | Source VERSION constant is 1.0.1. GHCR `:1.0.2` (`96e25631764b`) stays the published immutable image. Not a downgrade. |

### Still waiting on the owner

- Rotate chat-exposed credentials and the old keys still in git history.
- Rotate `cu-devsecshield-key.pem` (#39).
- Start 172.31.35.52.
- Decide `acm:GetCertificate`, the `excluded_by_policy` Q0 code, and client-cert trust stores.
- Delete leftover KMS key `59416634-…` (#60).
- Main promotion go-ahead.

### In progress by the other session (do not steal)

#42 #63 #41 #99 #146 #126 #102

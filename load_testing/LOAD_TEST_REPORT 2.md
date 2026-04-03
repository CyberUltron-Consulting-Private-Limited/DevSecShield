# DevSecShield Production Load Test Report

**Date:** 2026-04-01 14:36:41
**Target:** `https://devsecshieldapi.zeroshield.ai`
**Server:** EC2 t3a.medium (2 vCPU, 4GB RAM)
**Load Levels:** 5 (10 → 50 → 100 → 500 → 1000 concurrent users)
**Duration per Level:** 5 minutes
**Total Test Duration:** ~25 minutes + ramp-up time

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Requests | 85,134 |
| Total Failures | 2,788 |
| Overall Failure Rate | 3.27% |
| Load Levels Tested | 5 |

## Summary by Load Level

| Level | Users | Total Reqs | Failures | Fail % | Avg (ms) | Median (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |
|-------|-------|-----------|----------|--------|----------|-------------|----------|----------|----------|-----|
| ✅ Level 1 - Light (10 users) | 10 | 1,090 | 44 | 4.0% | 118 | 45 | 580 | 1500 | 2058 | 3.6 |
| ✅ Level 2 - Moderate (50 users) | 50 | 5,292 | 109 | 2.1% | 97 | 43 | 230 | 880 | 4010 | 17.7 |
| ✅ Level 3 - Medium (100 users) | 100 | 10,388 | 184 | 1.8% | 161 | 47 | 380 | 3200 | 10220 | 34.7 |
| ✅ Level 4 - Heavy (500 users) | 500 | 34,675 | 827 | 2.4% | 1505 | 1300 | 3200 | 5200 | 11167 | 115.8 |
| ✅ Level 5 - Stress (1000 users) | 1000 | 33,689 | 1,624 | 4.8% | 5949 | 5300 | 7500 | 23000 | 22811 | 112.2 |

## Detailed Results by Load Level

### Level 1 - Light (10 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 10 |
| Total Requests | 1,090 |
| Failed Requests | 44 (4.0%) |
| Avg Response Time | 118 ms |
| Median Response Time | 45 ms |
| 95th Percentile | 580 ms |
| 99th Percentile | 1500 ms |
| Min Response Time | 26 ms |
| Max Response Time | 2058 ms |
| Requests/sec | 3.6 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 7 | 0 | 48 | 52 | 52 | 0.0 |
| GET | `/admin/teams` | 9 | 0 | 76 | 150 | 146 | 0.0 |
| GET | `/admin/users` | 13 | 0 | 67 | 130 | 131 | 0.0 |
| GET | `/docs (health)` | 119 | 0 | 75 | 280 | 1479 | 0.4 |
| GET | `/get_user` | 66 | 0 | 73 | 140 | 693 | 0.2 |
| GET | `/get_user (no auth)` | 31 | 0 | 60 | 150 | 291 | 0.1 |
| POST | `/guardrails/{team_id}/integration (create)` | 9 | 0 | 92 | 400 | 403 | 0.0 |
| GET | `/guardrails/{team_id}/integrations` | 33 | 0 | 70 | 120 | 339 | 0.1 |
| POST | `/login` | 49 | 0 | 87 | 160 | 685 | 0.2 |
| POST | `/login (attempt)` | 8 | 8 | 863 | 1600 | 1572 | 0.0 |
| POST | `/login (invalid)` | 47 | 28 | 88 | 170 | 450 | 0.2 |
| GET | `/logout` | 10 | 0 | 49 | 120 | 118 | 0.0 |
| GET | `/openapi.json` | 72 | 0 | 170 | 460 | 1670 | 0.2 |
| POST | `/refresh` | 27 | 0 | 88 | 190 | 710 | 0.1 |
| POST | `/refresh (invalid)` | 23 | 0 | 51 | 120 | 151 | 0.1 |
| POST | `/reset_password` | 16 | 0 | 105 | 740 | 739 | 0.1 |
| POST | `/send_code` | 41 | 0 | 392 | 740 | 1259 | 0.1 |
| POST | `/send_code (setup)` | 8 | 0 | 1658 | 2100 | 2058 | 0.0 |
| POST | `/signup` | 26 | 0 | 65 | 130 | 161 | 0.1 |
| POST | `/signup (attempt)` | 8 | 8 | 986 | 1600 | 1580 | 0.0 |
| POST | `/team (create)` | 12 | 0 | 56 | 120 | 121 | 0.0 |
| GET | `/team/{team_id}` | 49 | 0 | 77 | 320 | 588 | 0.2 |
| PUT | `/team/{team_id} (update)` | 10 | 0 | 40 | 55 | 55 | 0.0 |
| GET | `/team/{team_id}/dashboard` | 49 | 0 | 61 | 150 | 344 | 0.2 |
| GET | `/teams` | 80 | 0 | 118 | 660 | 1449 | 0.3 |
| GET | `/teams/dashboard` | 28 | 0 | 57 | 120 | 125 | 0.1 |
| POST | `/{team_id}/cicd/integration (create)` | 14 | 0 | 98 | 620 | 620 | 0.0 |
| GET | `/{team_id}/cicd/integrations` | 27 | 0 | 57 | 110 | 160 | 0.1 |
| POST | `/{team_id}/{type}/scan (create)` | 23 | 0 | 65 | 130 | 130 | 0.1 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 54 | 0 | 79 | 170 | 560 | 0.2 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 10 | 0 | 46 | 93 | 93 | 0.0 |
| GET | `/{team_id}/{type}/scans` | 112 | 0 | 68 | 150 | 623 | 0.4 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 3 |
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 6 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 2 |
| POST | `/login (attempt)` | HTTPError('400 Client Error: Bad Request for url: /login (attempt)') | 5 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 28 |

### Level 2 - Moderate (50 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 50 |
| Total Requests | 5,292 |
| Failed Requests | 109 (2.1%) |
| Avg Response Time | 97 ms |
| Median Response Time | 43 ms |
| 95th Percentile | 230 ms |
| 99th Percentile | 880 ms |
| Min Response Time | 25 ms |
| Max Response Time | 4010 ms |
| Requests/sec | 17.7 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 62 | 0 | 72 | 130 | 653 | 0.2 |
| GET | `/admin/teams` | 50 | 0 | 68 | 140 | 151 | 0.2 |
| GET | `/admin/users` | 59 | 0 | 83 | 290 | 489 | 0.2 |
| GET | `/docs (health)` | 554 | 0 | 75 | 180 | 1757 | 1.9 |
| GET | `/get_user` | 289 | 0 | 71 | 170 | 991 | 1.0 |
| GET | `/get_user (no auth)` | 116 | 0 | 62 | 120 | 756 | 0.4 |
| POST | `/guardrails/{team_id}/integration (create)` | 58 | 0 | 90 | 390 | 808 | 0.2 |
| GET | `/guardrails/{team_id}/integrations` | 155 | 0 | 90 | 360 | 808 | 0.5 |
| POST | `/login` | 172 | 0 | 88 | 250 | 1090 | 0.6 |
| POST | `/login (attempt)` | 40 | 40 | 168 | 730 | 3147 | 0.1 |
| POST | `/login (invalid)` | 247 | 29 | 92 | 160 | 3764 | 0.8 |
| GET | `/logout` | 39 | 0 | 80 | 490 | 549 | 0.1 |
| GET | `/openapi.json` | 372 | 0 | 142 | 250 | 2794 | 1.2 |
| POST | `/refresh` | 107 | 0 | 63 | 240 | 557 | 0.4 |
| POST | `/refresh (invalid)` | 115 | 0 | 67 | 140 | 656 | 0.4 |
| POST | `/reset_password` | 59 | 0 | 71 | 160 | 574 | 0.2 |
| POST | `/send_code` | 151 | 0 | 145 | 720 | 1264 | 0.5 |
| POST | `/send_code (setup)` | 40 | 31 | 1434 | 3800 | 4010 | 0.1 |
| POST | `/signup` | 158 | 0 | 68 | 150 | 1015 | 0.5 |
| POST | `/signup (attempt)` | 9 | 9 | 2102 | 3800 | 3794 | 0.0 |
| POST | `/team (create)` | 57 | 0 | 66 | 160 | 415 | 0.2 |
| GET | `/team/{team_id}` | 294 | 0 | 68 | 140 | 820 | 1.0 |
| PUT | `/team/{team_id} (update)` | 56 | 0 | 62 | 180 | 390 | 0.2 |
| GET | `/team/{team_id}/dashboard` | 259 | 0 | 70 | 140 | 846 | 0.9 |
| GET | `/teams` | 411 | 0 | 84 | 260 | 1055 | 1.4 |
| GET | `/teams/dashboard` | 142 | 0 | 71 | 150 | 604 | 0.5 |
| POST | `/{team_id}/cicd/integration (create)` | 49 | 0 | 88 | 130 | 812 | 0.2 |
| GET | `/{team_id}/cicd/integrations` | 158 | 0 | 78 | 200 | 494 | 0.5 |
| POST | `/{team_id}/{type}/scan (create)` | 104 | 0 | 62 | 120 | 437 | 0.3 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 297 | 0 | 81 | 170 | 900 | 1.0 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 53 | 0 | 60 | 140 | 335 | 0.2 |
| GET | `/{team_id}/{type}/scans` | 560 | 0 | 77 | 180 | 1034 | 1.9 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 40 |
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 3 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 6 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 31 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 29 |

### Level 3 - Medium (100 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 100 |
| Total Requests | 10,388 |
| Failed Requests | 184 (1.8%) |
| Avg Response Time | 161 ms |
| Median Response Time | 47 ms |
| 95th Percentile | 380 ms |
| 99th Percentile | 3200 ms |
| Min Response Time | 25 ms |
| Max Response Time | 10220 ms |
| Requests/sec | 34.7 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 106 | 0 | 109 | 530 | 843 | 0.4 |
| GET | `/admin/teams` | 99 | 0 | 80 | 170 | 608 | 0.3 |
| GET | `/admin/users` | 103 | 0 | 115 | 520 | 861 | 0.3 |
| GET | `/docs (health)` | 1145 | 0 | 146 | 350 | 9176 | 3.8 |
| GET | `/get_user` | 538 | 0 | 79 | 320 | 1009 | 1.8 |
| GET | `/get_user (no auth)` | 227 | 0 | 70 | 270 | 568 | 0.8 |
| POST | `/guardrails/{team_id}/integration (create)` | 116 | 0 | 84 | 260 | 615 | 0.4 |
| GET | `/guardrails/{team_id}/integrations` | 316 | 0 | 103 | 430 | 1033 | 1.1 |
| POST | `/login` | 344 | 0 | 76 | 250 | 1000 | 1.2 |
| POST | `/login (attempt)` | 80 | 80 | 220 | 270 | 1548 | 0.3 |
| POST | `/login (invalid)` | 434 | 24 | 95 | 260 | 8184 | 1.5 |
| GET | `/logout` | 97 | 0 | 66 | 130 | 550 | 0.3 |
| GET | `/openapi.json` | 702 | 0 | 209 | 340 | 10220 | 2.3 |
| POST | `/refresh` | 231 | 0 | 70 | 180 | 584 | 0.8 |
| POST | `/refresh (invalid)` | 237 | 0 | 79 | 270 | 1233 | 0.8 |
| POST | `/reset_password` | 94 | 0 | 79 | 220 | 1188 | 0.3 |
| POST | `/send_code` | 329 | 0 | 114 | 640 | 1171 | 1.1 |
| POST | `/send_code (setup)` | 80 | 62 | 6457 | 10000 | 10178 | 0.3 |
| POST | `/signup` | 347 | 0 | 70 | 160 | 930 | 1.2 |
| POST | `/signup (attempt)` | 18 | 18 | 5404 | 9500 | 9533 | 0.1 |
| POST | `/team (create)` | 104 | 0 | 66 | 130 | 563 | 0.3 |
| GET | `/team/{team_id}` | 549 | 0 | 81 | 270 | 883 | 1.8 |
| PUT | `/team/{team_id} (update)` | 94 | 0 | 94 | 530 | 1082 | 0.3 |
| GET | `/team/{team_id}/dashboard` | 520 | 0 | 81 | 290 | 961 | 1.7 |
| GET | `/teams` | 841 | 0 | 92 | 390 | 1004 | 2.8 |
| GET | `/teams/dashboard` | 317 | 0 | 80 | 350 | 618 | 1.1 |
| POST | `/{team_id}/cicd/integration (create)` | 103 | 0 | 93 | 280 | 674 | 0.3 |
| GET | `/{team_id}/cicd/integrations` | 329 | 0 | 97 | 350 | 1079 | 1.1 |
| POST | `/{team_id}/{type}/scan (create)` | 220 | 0 | 105 | 510 | 1164 | 0.7 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 506 | 0 | 94 | 350 | 1070 | 1.7 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 96 | 0 | 62 | 140 | 369 | 0.3 |
| GET | `/{team_id}/{type}/scans` | 1066 | 0 | 84 | 290 | 1136 | 3.6 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 80 |
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 2 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 16 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 62 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 24 |

### Level 4 - Heavy (500 users)

**Performance Rating:** 🔴 Poor

| Metric | Value |
|--------|-------|
| Concurrent Users | 500 |
| Total Requests | 34,675 |
| Failed Requests | 827 (2.4%) |
| Avg Response Time | 1505 ms |
| Median Response Time | 1300 ms |
| 95th Percentile | 3200 ms |
| 99th Percentile | 5200 ms |
| Min Response Time | 367 ms |
| Max Response Time | 11167 ms |
| Requests/sec | 115.8 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 336 | 0 | 1525 | 3300 | 5282 | 1.1 |
| GET | `/admin/teams` | 375 | 0 | 1505 | 2700 | 5316 | 1.3 |
| GET | `/admin/users` | 353 | 0 | 1507 | 3200 | 5304 | 1.2 |
| GET | `/docs (health)` | 3511 | 0 | 1465 | 2800 | 10225 | 11.7 |
| GET | `/get_user` | 1891 | 0 | 1467 | 3000 | 5322 | 6.3 |
| GET | `/get_user (no auth)` | 726 | 0 | 1477 | 3000 | 8328 | 2.4 |
| POST | `/guardrails/{team_id}/integration (create)` | 402 | 0 | 1487 | 3400 | 5289 | 1.3 |
| GET | `/guardrails/{team_id}/integrations` | 1108 | 0 | 1521 | 3200 | 5365 | 3.7 |
| POST | `/login` | 1099 | 0 | 1457 | 3100 | 5312 | 3.7 |
| POST | `/login (attempt)` | 400 | 400 | 694 | 1200 | 1270 | 1.3 |
| POST | `/login (invalid)` | 1389 | 27 | 1491 | 3200 | 9315 | 4.6 |
| GET | `/logout` | 368 | 0 | 1485 | 3000 | 5279 | 1.2 |
| GET | `/openapi.json` | 1994 | 0 | 1574 | 3400 | 10318 | 6.7 |
| POST | `/refresh` | 762 | 0 | 1500 | 3400 | 5344 | 2.5 |
| POST | `/refresh (invalid)` | 680 | 0 | 1485 | 3300 | 10148 | 2.3 |
| POST | `/reset_password` | 354 | 0 | 1472 | 3100 | 5409 | 1.2 |
| POST | `/send_code` | 1120 | 0 | 1461 | 3200 | 5292 | 3.7 |
| POST | `/send_code (setup)` | 400 | 383 | 3849 | 10000 | 11167 | 1.3 |
| POST | `/signup` | 1063 | 0 | 1499 | 3200 | 5246 | 3.5 |
| POST | `/signup (attempt)` | 17 | 17 | 5456 | 10000 | 10162 | 0.1 |
| POST | `/team (create)` | 388 | 0 | 1497 | 2900 | 5270 | 1.3 |
| GET | `/team/{team_id}` | 1859 | 0 | 1496 | 3300 | 5331 | 6.2 |
| PUT | `/team/{team_id} (update)` | 383 | 0 | 1465 | 2400 | 5351 | 1.3 |
| GET | `/team/{team_id}/dashboard` | 1820 | 0 | 1477 | 3100 | 5338 | 6.1 |
| GET | `/teams` | 2881 | 0 | 1485 | 3100 | 5373 | 9.6 |
| GET | `/teams/dashboard` | 1110 | 0 | 1445 | 2600 | 5305 | 3.7 |
| POST | `/{team_id}/cicd/integration (create)` | 399 | 0 | 1497 | 3400 | 5300 | 1.3 |
| GET | `/{team_id}/cicd/integrations` | 1068 | 0 | 1481 | 3100 | 5367 | 3.6 |
| POST | `/{team_id}/{type}/scan (create)` | 743 | 0 | 1515 | 3400 | 5313 | 2.5 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 1752 | 0 | 1474 | 3100 | 5370 | 5.9 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 344 | 0 | 1509 | 3200 | 5358 | 1.1 |
| GET | `/{team_id}/{type}/scans` | 3580 | 0 | 1460 | 2700 | 5354 | 12.0 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 400 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 17 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 383 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 27 |

### Level 5 - Stress (1000 users)

**Performance Rating:** 🔴 Poor

| Metric | Value |
|--------|-------|
| Concurrent Users | 1000 |
| Total Requests | 33,689 |
| Failed Requests | 1,624 (4.8%) |
| Avg Response Time | 5949 ms |
| Median Response Time | 5300 ms |
| 95th Percentile | 7500 ms |
| 99th Percentile | 23000 ms |
| Min Response Time | 1115 ms |
| Max Response Time | 22811 ms |
| Requests/sec | 112.2 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 362 | 0 | 6171 | 7700 | 22717 | 1.2 |
| GET | `/admin/teams` | 339 | 0 | 5998 | 7400 | 22681 | 1.1 |
| GET | `/admin/users` | 343 | 0 | 6296 | 7800 | 22719 | 1.1 |
| GET | `/docs (health)` | 2988 | 0 | 5905 | 7400 | 22723 | 10.0 |
| GET | `/get_user` | 1756 | 0 | 6150 | 7500 | 22797 | 5.9 |
| GET | `/get_user (no auth)` | 603 | 0 | 6038 | 7400 | 22731 | 2.0 |
| POST | `/guardrails/{team_id}/integration (create)` | 388 | 0 | 6040 | 7400 | 22712 | 1.3 |
| GET | `/guardrails/{team_id}/integrations` | 1084 | 0 | 6132 | 7600 | 22808 | 3.6 |
| POST | `/login` | 1099 | 0 | 5974 | 7400 | 22716 | 3.7 |
| POST | `/login (attempt)` | 800 | 800 | 2123 | 4200 | 4946 | 2.7 |
| POST | `/login (invalid)` | 1172 | 24 | 6122 | 7600 | 22742 | 3.9 |
| GET | `/logout` | 366 | 0 | 6090 | 7400 | 22730 | 1.2 |
| GET | `/openapi.json` | 1858 | 0 | 6161 | 7600 | 22811 | 6.2 |
| POST | `/refresh` | 759 | 0 | 6125 | 7500 | 22737 | 2.5 |
| POST | `/refresh (invalid)` | 579 | 0 | 5930 | 7400 | 22687 | 1.9 |
| POST | `/reset_password` | 392 | 0 | 6134 | 7400 | 22690 | 1.3 |
| POST | `/send_code` | 1052 | 0 | 6009 | 7400 | 22803 | 3.5 |
| POST | `/send_code (setup)` | 800 | 780 | 5979 | 12000 | 12889 | 2.7 |
| POST | `/signup` | 1038 | 0 | 5989 | 7400 | 22734 | 3.5 |
| POST | `/signup (attempt)` | 20 | 20 | 6480 | 12000 | 11758 | 0.1 |
| POST | `/team (create)` | 333 | 0 | 5864 | 7400 | 22747 | 1.1 |
| GET | `/team/{team_id}` | 1754 | 0 | 5995 | 7400 | 22724 | 5.8 |
| PUT | `/team/{team_id} (update)` | 352 | 0 | 6164 | 7400 | 22754 | 1.2 |
| GET | `/team/{team_id}/dashboard` | 1794 | 0 | 5923 | 7400 | 22779 | 6.0 |
| GET | `/teams` | 2818 | 0 | 6026 | 7400 | 22784 | 9.4 |
| GET | `/teams/dashboard` | 1092 | 0 | 6118 | 7500 | 22803 | 3.6 |
| POST | `/{team_id}/cicd/integration (create)` | 360 | 0 | 6387 | 22000 | 22717 | 1.2 |
| GET | `/{team_id}/cicd/integrations` | 1058 | 0 | 6086 | 7500 | 22718 | 3.5 |
| POST | `/{team_id}/{type}/scan (create)` | 708 | 0 | 5978 | 7500 | 22726 | 2.4 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 1735 | 0 | 5989 | 7400 | 22795 | 5.8 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 356 | 0 | 6163 | 7600 | 22755 | 1.2 |
| GET | `/{team_id}/{type}/scans` | 3531 | 0 | 6056 | 7500 | 22781 | 11.8 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 800 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 20 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 780 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 24 |

## Failure Analysis

### Failure Categories

#### `POST /login (attempt)`

**Affected Load Levels:** Level 3 - Medium (100 users), Level 5 - Stress (1000 users), Level 1 - Light (10 users), Level 4 - Heavy (500 users), Level 2 - Moderate (50 users)

- **Error:** `HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)')`
  - **Total Occurrences:** 1323
- **Error:** `HTTPError('400 Client Error: Bad Request for url: /login (attempt)')`
  - **Total Occurrences:** 5

#### `POST /signup (attempt)`

**Affected Load Levels:** Level 3 - Medium (100 users), Level 5 - Stress (1000 users), Level 1 - Light (10 users), Level 4 - Heavy (500 users), Level 2 - Moderate (50 users)

- **Error:** `HTTPError('400 Client Error: Bad Request for url: /signup (attempt)')`
  - **Total Occurrences:** 11
- **Error:** `HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)')`
  - **Total Occurrences:** 61

#### `POST /login (invalid)`

**Affected Load Levels:** Level 3 - Medium (100 users), Level 5 - Stress (1000 users), Level 1 - Light (10 users), Level 4 - Heavy (500 users), Level 2 - Moderate (50 users)

- **Error:** `CatchResponseError('Unexpected status: 400')`
  - **Total Occurrences:** 132

#### `POST /send_code (setup)`

**Affected Load Levels:** Level 4 - Heavy (500 users), Level 3 - Medium (100 users), Level 2 - Moderate (50 users), Level 5 - Stress (1000 users)

- **Error:** `HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)')`
  - **Total Occurrences:** 1256

## Root Cause Analysis

### Performance Degradation Pattern

- **Significant degradation detected at 100 users**: avg response time increased by 66% (from 97ms to 161ms)

- **Significant degradation detected at 500 users**: avg response time increased by 837% (from 161ms to 1505ms)

- **Significant degradation detected at 1000 users**: avg response time increased by 295% (from 1505ms to 5949ms)

### Potential Bottlenecks


Based on the test results and the system architecture (EC2 t3a.medium: 2 vCPU, 4 GB RAM), the following potential bottlenecks should be investigated:

1. **CPU Saturation (t3a.medium = 2 vCPUs)**
   - FastAPI runs on a single process by default (Uvicorn)
   - Under high concurrency, CPU-bound operations (JWT validation, bcrypt hashing, JSON serialization) saturate cores
   - **Impact:** Response time linearly increases, request queuing occurs

2. **Memory Pressure (4 GB RAM)**
   - PostgreSQL, MongoDB, RabbitMQ, and the application server all share 4 GB
   - Under load, connection pools grow, in-memory caches expand, and OOM kills can occur
   - **Impact:** Service crashes, swap thrashing, extreme latency spikes

3. **Database Connection Pool Exhaustion**
   - PostgreSQL default connection limit is 100
   - With 500+ concurrent users, connection pool becomes the bottleneck
   - **Impact:** Requests queue waiting for DB connections, timeout errors

4. **Rate Limiting**
   - Backend has rate limiting: 20 requests/30s per IP for most endpoints
   - Public guardrails: 2 requests/10s
   - **Impact:** 429 (Too Many Requests) responses dominate under load

5. **Single-Instance Deployment**
   - No horizontal scaling (single EC2 instance)
   - No load balancer for distributing traffic
   - **Impact:** Single point of failure, no ability to handle burst traffic

6. **Network I/O (t3a.medium = Up to 5 Gbps)**
   - SSL/TLS handshake overhead per connection
   - No connection pooling on the client side
   - **Impact:** Connection establishment delays under high concurrency

7. **Worker Thread Starvation**
   - Celery workers share the same instance resources
   - Under load, scan workers and API server compete for CPU/memory
   - **Impact:** Both API latency and scan processing times degrade

## Recommendations

### Immediate Fixes (Priority 1)


| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Add Uvicorn workers** (`uvicorn main:app --workers 4`) | 2-3x throughput increase | Low |
| 2 | **Increase PostgreSQL `max_connections`** to 200+ | Eliminate connection pool exhaustion | Low |
| 3 | **Add connection pooling** (PgBouncer) | 5-10x connection reuse efficiency | Medium |
| 4 | **Upgrade to t3a.large** (or xlarge) | 2-4x CPU/memory headroom | Low |
| 5 | **Configure Gunicorn** with worker class `uvicorn.workers.UvicornWorker` | Production-grade process management | Low |

### Short-Term Improvements (Priority 2)


| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Add Redis caching** for dashboard/team queries | 50-80% latency reduction on reads | Medium |
| 2 | **Move Celery workers to separate instance(s)** | Eliminate resource contention | Medium |
| 3 | **Add ALB (Application Load Balancer)** with 2+ instances | Linear horizontal scaling | Medium |
| 4 | **Implement API response caching** (stale-while-revalidate) | Reduces DB load by 60-80% | Medium |
| 5 | **Add health check endpoint** (`/health`) without auth | Proper monitoring and ALB health checks | Low |

### Long-Term Architecture (Priority 3)


| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Auto-scaling group** with min=2, max=8 instances | Handle traffic spikes automatically | High |
| 2 | **RDS (Managed PostgreSQL)** instead of self-hosted | Connection management, backups, replicas | Medium |
| 3 | **ElastiCache (Redis)** for session/rate-limit state | Distributed rate limiting and caching | Medium |
| 4 | **CloudFront CDN** for frontend + API caching | Global latency reduction | Medium |
| 5 | **Container orchestration** (ECS/EKS) | Better resource utilization, rolling deployments | High |
| 6 | **Read replicas for PostgreSQL** | Offload read-heavy dashboard queries | Medium |
| 7 | **MongoDB Atlas** (managed) with proper indexes | Query optimization, auto-scaling storage | Medium |

## Capacity Planning Estimates


Based on the t3a.medium instance (2 vCPU, 4 GB RAM):

| Scenario | Est. Max Concurrent Users | Recommended Instance | Notes |
|----------|--------------------------|---------------------|-------|
| Development/Staging | 10-20 | t3a.medium | Current setup |
| Small Production (< 50 users) | 30-50 | t3a.large | 2 vCPU, 8 GB RAM |
| Medium Production (< 200 users) | 100-200 | t3a.xlarge + RDS | 4 vCPU, 16 GB RAM |
| Large Production (< 1000 users) | 500-1000 | 2x t3a.xlarge + ALB + RDS | Horizontal scaling |
| Enterprise (1000+ users) | 1000+ | Auto-scaling group + managed services | Full cloud-native |

## Test Configuration Reference


```
Target: https://devsecshieldapi.zeroshield.ai
Server: EC2 t3a.medium (2 vCPU, 4 GB RAM)
Tool: Locust 2.34.0
Load Levels:
  Level 1: 10 users, spawn rate 2/s, duration 5m
  Level 2: 50 users, spawn rate 5/s, duration 5m
  Level 3: 100 users, spawn rate 10/s, duration 5m
  Level 4: 500 users, spawn rate 25/s, duration 5m
  Level 5: 1000 users, spawn rate 50/s, duration 5m

Endpoints Tested:
  - Auth: /send_code, /signup, /login, /refresh, /get_user, /reset_password, /logout
  - Teams: /teams, /team/{id}, /team/{id}/dashboard, /teams/dashboard, create/update
  - Scans: /{team_id}/{type}/scans, /{team_id}/{type}/scan/{id}, create/update
  - Guardrails: /guardrails/{team_id}/integrations, create
  - CI/CD: /{team_id}/cicd/integrations, create
  - Admin: /admin/check_superuser, /admin/teams, /admin/users
  - Public: /docs, /openapi.json
```

---

*Report generated on 2026-04-01 14:36:41 by DevSecShield Load Testing Suite*

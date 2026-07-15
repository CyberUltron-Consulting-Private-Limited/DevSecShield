# DevSecShield Production Load Test Report

**Date:** 2026-04-03 01:39:07
**Target:** `https://devsecshieldapi.zeroshield.ai`
**Server:** EC2 t3a.medium (2 vCPU, 4GB RAM)
**Load Levels:** 5 (10 → 50 → 100 → 500 → 1000 concurrent users)
**Duration per Level:** 5 minutes
**Total Test Duration:** ~25 minutes + ramp-up time

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Requests | 128,616 |
| Total Failures | 3,172 |
| Overall Failure Rate | 2.47% |
| Load Levels Tested | 5 |

## Summary by Load Level

| Level | Users | Total Reqs | Failures | Fail % | Avg (ms) | Median (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |
|-------|-------|-----------|----------|--------|----------|-------------|----------|----------|----------|-----|
| ⚠️ Level 1 - Light (10 users) | 10 | 1,079 | 59 | 5.5% | 89 | 67 | 170 | 340 | 999 | 3.6 |
| ✅ Level 2 - Moderate (50 users) | 50 | 5,352 | 170 | 3.2% | 88 | 62 | 190 | 330 | 958 | 17.9 |
| ✅ Level 3 - Medium (100 users) | 100 | 10,611 | 255 | 2.4% | 95 | 63 | 230 | 380 | 1185 | 35.5 |
| ✅ Level 4 - Heavy (500 users) | 500 | 41,807 | 938 | 2.2% | 777 | 330 | 2700 | 8200 | 63301 | 139.8 |
| ✅ Level 5 - Stress (1000 users) | 1000 | 69,767 | 1,750 | 2.5% | 1450 | 630 | 4600 | 16000 | 96420 | 233.3 |

## Detailed Results by Load Level

### Level 1 - Light (10 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 10 |
| Total Requests | 1,079 |
| Failed Requests | 59 (5.5%) |
| Avg Response Time | 89 ms |
| Median Response Time | 67 ms |
| 95th Percentile | 170 ms |
| 99th Percentile | 340 ms |
| Min Response Time | 28 ms |
| Max Response Time | 999 ms |
| Requests/sec | 3.6 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 9 | 0 | 103 | 300 | 296 | 0.0 |
| GET | `/admin/teams` | 9 | 0 | 83 | 130 | 134 | 0.0 |
| GET | `/admin/users` | 11 | 0 | 91 | 170 | 174 | 0.0 |
| GET | `/docs (health)` | 126 | 0 | 60 | 140 | 180 | 0.4 |
| GET | `/get_user` | 50 | 0 | 80 | 160 | 169 | 0.2 |
| GET | `/get_user (no auth)` | 22 | 0 | 78 | 140 | 149 | 0.1 |
| POST | `/guardrails/{team_id}/integration (create)` | 14 | 0 | 71 | 130 | 126 | 0.0 |
| GET | `/guardrails/{team_id}/integrations` | 33 | 0 | 82 | 150 | 164 | 0.1 |
| POST | `/login` | 46 | 0 | 115 | 190 | 271 | 0.2 |
| POST | `/login (attempt)` | 8 | 8 | 151 | 250 | 253 | 0.0 |
| POST | `/login (invalid)` | 45 | 43 | 135 | 250 | 529 | 0.2 |
| GET | `/logout` | 19 | 0 | 81 | 150 | 151 | 0.1 |
| GET | `/openapi.json` | 63 | 0 | 142 | 210 | 999 | 0.2 |
| POST | `/refresh` | 23 | 0 | 74 | 150 | 161 | 0.1 |
| POST | `/refresh (invalid)` | 24 | 0 | 98 | 170 | 179 | 0.1 |
| POST | `/reset_password` | 10 | 0 | 110 | 210 | 213 | 0.0 |
| POST | `/send_code` | 26 | 0 | 102 | 160 | 237 | 0.1 |
| POST | `/send_code (setup)` | 8 | 0 | 368 | 530 | 531 | 0.0 |
| POST | `/signup` | 27 | 0 | 124 | 210 | 221 | 0.1 |
| POST | `/signup (attempt)` | 8 | 8 | 114 | 210 | 211 | 0.0 |
| POST | `/team (create)` | 12 | 0 | 75 | 160 | 162 | 0.0 |
| GET | `/team/{team_id}` | 47 | 0 | 76 | 160 | 170 | 0.2 |
| PUT | `/team/{team_id} (update)` | 7 | 0 | 57 | 61 | 61 | 0.0 |
| GET | `/team/{team_id}/dashboard` | 58 | 0 | 75 | 160 | 383 | 0.2 |
| GET | `/teams` | 89 | 0 | 76 | 150 | 285 | 0.3 |
| GET | `/teams/dashboard` | 32 | 0 | 82 | 140 | 384 | 0.1 |
| POST | `/{team_id}/cicd/integration (create)` | 7 | 0 | 100 | 140 | 143 | 0.0 |
| GET | `/{team_id}/cicd/integrations` | 36 | 0 | 71 | 140 | 190 | 0.1 |
| POST | `/{team_id}/{type}/scan (create)` | 22 | 0 | 87 | 150 | 307 | 0.1 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 55 | 0 | 79 | 160 | 173 | 0.2 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 10 | 0 | 84 | 170 | 171 | 0.0 |
| GET | `/{team_id}/{type}/scans` | 123 | 0 | 71 | 140 | 302 | 0.4 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 8 |
| POST | `/login (attempt)` | HTTPError('400 Client Error: Bad Request for url: /login (attempt)') | 8 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 43 |

### Level 2 - Moderate (50 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 50 |
| Total Requests | 5,352 |
| Failed Requests | 170 (3.2%) |
| Avg Response Time | 88 ms |
| Median Response Time | 62 ms |
| 95th Percentile | 190 ms |
| 99th Percentile | 330 ms |
| Min Response Time | 28 ms |
| Max Response Time | 958 ms |
| Requests/sec | 17.9 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 52 | 0 | 83 | 210 | 264 | 0.2 |
| GET | `/admin/teams` | 41 | 0 | 85 | 160 | 190 | 0.1 |
| GET | `/admin/users` | 57 | 0 | 83 | 180 | 220 | 0.2 |
| GET | `/docs (health)` | 620 | 0 | 72 | 150 | 459 | 2.1 |
| GET | `/get_user` | 255 | 0 | 77 | 150 | 693 | 0.9 |
| GET | `/get_user (no auth)` | 126 | 0 | 80 | 200 | 389 | 0.4 |
| POST | `/guardrails/{team_id}/integration (create)` | 48 | 0 | 90 | 180 | 263 | 0.2 |
| GET | `/guardrails/{team_id}/integrations` | 159 | 0 | 77 | 160 | 366 | 0.5 |
| POST | `/login` | 185 | 0 | 99 | 190 | 436 | 0.6 |
| POST | `/login (attempt)` | 40 | 40 | 119 | 190 | 393 | 0.1 |
| POST | `/login (invalid)` | 198 | 90 | 104 | 220 | 374 | 0.7 |
| GET | `/logout` | 56 | 0 | 63 | 130 | 152 | 0.2 |
| GET | `/openapi.json` | 348 | 0 | 151 | 250 | 958 | 1.2 |
| POST | `/refresh` | 132 | 0 | 85 | 160 | 312 | 0.4 |
| POST | `/refresh (invalid)` | 118 | 0 | 90 | 200 | 386 | 0.4 |
| POST | `/reset_password` | 51 | 0 | 96 | 190 | 239 | 0.2 |
| POST | `/send_code` | 179 | 0 | 102 | 190 | 567 | 0.6 |
| POST | `/send_code (setup)` | 40 | 18 | 296 | 430 | 486 | 0.1 |
| POST | `/signup` | 150 | 0 | 102 | 190 | 312 | 0.5 |
| POST | `/signup (attempt)` | 22 | 22 | 107 | 140 | 153 | 0.1 |
| POST | `/team (create)` | 57 | 0 | 77 | 150 | 460 | 0.2 |
| GET | `/team/{team_id}` | 286 | 0 | 76 | 150 | 479 | 1.0 |
| PUT | `/team/{team_id} (update)` | 47 | 0 | 117 | 320 | 428 | 0.2 |
| GET | `/team/{team_id}/dashboard` | 266 | 0 | 74 | 140 | 397 | 0.9 |
| GET | `/teams` | 422 | 0 | 73 | 140 | 543 | 1.4 |
| GET | `/teams/dashboard` | 181 | 0 | 73 | 140 | 380 | 0.6 |
| POST | `/{team_id}/cicd/integration (create)` | 41 | 0 | 94 | 190 | 321 | 0.1 |
| GET | `/{team_id}/cicd/integrations` | 166 | 0 | 80 | 160 | 465 | 0.6 |
| POST | `/{team_id}/{type}/scan (create)` | 104 | 0 | 90 | 170 | 353 | 0.3 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 263 | 0 | 79 | 160 | 350 | 0.9 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 60 | 0 | 90 | 170 | 227 | 0.2 |
| GET | `/{team_id}/{type}/scans` | 582 | 0 | 76 | 150 | 532 | 1.9 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 17 |
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 18 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 4 |
| POST | `/login (attempt)` | HTTPError('400 Client Error: Bad Request for url: /login (attempt)') | 23 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 18 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 90 |

### Level 3 - Medium (100 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 100 |
| Total Requests | 10,611 |
| Failed Requests | 255 (2.4%) |
| Avg Response Time | 95 ms |
| Median Response Time | 63 ms |
| 95th Percentile | 230 ms |
| 99th Percentile | 380 ms |
| Min Response Time | 28 ms |
| Max Response Time | 1185 ms |
| Requests/sec | 35.5 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 118 | 0 | 84 | 190 | 279 | 0.4 |
| GET | `/admin/teams` | 105 | 0 | 83 | 160 | 311 | 0.4 |
| GET | `/admin/users` | 116 | 0 | 95 | 270 | 435 | 0.4 |
| GET | `/docs (health)` | 1161 | 0 | 77 | 180 | 679 | 3.9 |
| GET | `/get_user` | 593 | 0 | 80 | 190 | 447 | 2.0 |
| GET | `/get_user (no auth)` | 228 | 0 | 81 | 190 | 721 | 0.8 |
| POST | `/guardrails/{team_id}/integration (create)` | 116 | 0 | 98 | 210 | 396 | 0.4 |
| GET | `/guardrails/{team_id}/integrations` | 343 | 0 | 91 | 180 | 725 | 1.1 |
| POST | `/login` | 317 | 0 | 101 | 210 | 510 | 1.1 |
| POST | `/login (attempt)` | 80 | 80 | 97 | 230 | 274 | 0.3 |
| POST | `/login (invalid)` | 440 | 95 | 110 | 280 | 531 | 1.5 |
| GET | `/logout` | 95 | 0 | 75 | 160 | 333 | 0.3 |
| GET | `/openapi.json` | 743 | 0 | 169 | 340 | 1185 | 2.5 |
| POST | `/refresh` | 238 | 0 | 98 | 240 | 597 | 0.8 |
| POST | `/refresh (invalid)` | 208 | 0 | 97 | 280 | 483 | 0.7 |
| POST | `/reset_password` | 100 | 0 | 97 | 280 | 666 | 0.3 |
| POST | `/send_code` | 305 | 0 | 93 | 200 | 355 | 1.0 |
| POST | `/send_code (setup)` | 80 | 55 | 322 | 450 | 534 | 0.3 |
| POST | `/signup` | 314 | 0 | 99 | 210 | 441 | 1.1 |
| POST | `/signup (attempt)` | 25 | 25 | 154 | 280 | 294 | 0.1 |
| POST | `/team (create)` | 113 | 0 | 94 | 240 | 355 | 0.4 |
| GET | `/team/{team_id}` | 536 | 0 | 80 | 170 | 636 | 1.8 |
| PUT | `/team/{team_id} (update)` | 94 | 0 | 93 | 200 | 791 | 0.3 |
| GET | `/team/{team_id}/dashboard` | 536 | 0 | 82 | 170 | 651 | 1.8 |
| GET | `/teams` | 887 | 0 | 81 | 180 | 793 | 3.0 |
| GET | `/teams/dashboard` | 346 | 0 | 80 | 170 | 417 | 1.2 |
| POST | `/{team_id}/cicd/integration (create)` | 125 | 0 | 105 | 200 | 533 | 0.4 |
| GET | `/{team_id}/cicd/integrations` | 342 | 0 | 88 | 180 | 470 | 1.1 |
| POST | `/{team_id}/{type}/scan (create)` | 205 | 0 | 104 | 230 | 462 | 0.7 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 563 | 0 | 90 | 200 | 539 | 1.9 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 103 | 0 | 103 | 240 | 427 | 0.3 |
| GET | `/{team_id}/{type}/scans` | 1036 | 0 | 81 | 190 | 618 | 3.5 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 64 |
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 14 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 11 |
| POST | `/login (attempt)` | HTTPError('400 Client Error: Bad Request for url: /login (attempt)') | 16 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 55 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 95 |

### Level 4 - Heavy (500 users)

**Performance Rating:** 🟠 Degraded

| Metric | Value |
|--------|-------|
| Concurrent Users | 500 |
| Total Requests | 41,807 |
| Failed Requests | 938 (2.2%) |
| Avg Response Time | 777 ms |
| Median Response Time | 330 ms |
| 95th Percentile | 2700 ms |
| 99th Percentile | 8200 ms |
| Min Response Time | 29 ms |
| Max Response Time | 63301 ms |
| Requests/sec | 139.8 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 446 | 0 | 625 | 2400 | 10619 | 1.5 |
| GET | `/admin/teams` | 469 | 0 | 649 | 2200 | 16116 | 1.6 |
| GET | `/admin/users` | 438 | 0 | 603 | 2200 | 9652 | 1.5 |
| GET | `/docs (health)` | 4247 | 21 | 648 | 2200 | 32475 | 14.2 |
| GET | `/get_user` | 2226 | 0 | 557 | 2000 | 11054 | 7.4 |
| GET | `/get_user (no auth)` | 772 | 5 | 625 | 2300 | 15469 | 2.6 |
| POST | `/guardrails/{team_id}/integration (create)` | 461 | 0 | 564 | 2000 | 6524 | 1.5 |
| GET | `/guardrails/{team_id}/integrations` | 1286 | 0 | 563 | 2000 | 18409 | 4.3 |
| POST | `/login` | 1336 | 0 | 598 | 2000 | 14014 | 4.5 |
| POST | `/login (attempt)` | 400 | 400 | 3030 | 11000 | 36051 | 1.3 |
| POST | `/login (invalid)` | 1761 | 102 | 619 | 2000 | 21951 | 5.9 |
| GET | `/logout` | 430 | 0 | 568 | 2300 | 7697 | 1.4 |
| GET | `/openapi.json` | 2528 | 7 | 1516 | 5100 | 32094 | 8.5 |
| POST | `/refresh` | 891 | 0 | 615 | 2500 | 7546 | 3.0 |
| POST | `/refresh (invalid)` | 854 | 3 | 632 | 1900 | 24304 | 2.9 |
| POST | `/reset_password` | 464 | 0 | 594 | 2100 | 8202 | 1.6 |
| POST | `/send_code` | 1284 | 0 | 608 | 2400 | 10850 | 4.3 |
| POST | `/send_code (setup)` | 400 | 373 | 9342 | 24000 | 63301 | 1.3 |
| POST | `/signup` | 1360 | 0 | 616 | 2100 | 16155 | 4.5 |
| POST | `/signup (attempt)` | 27 | 27 | 1253 | 2500 | 17350 | 0.1 |
| POST | `/team (create)` | 481 | 0 | 602 | 2000 | 20712 | 1.6 |
| GET | `/team/{team_id}` | 2214 | 0 | 665 | 2500 | 19149 | 7.4 |
| PUT | `/team/{team_id} (update)` | 445 | 0 | 609 | 2000 | 27673 | 1.5 |
| GET | `/team/{team_id}/dashboard` | 2144 | 0 | 621 | 2300 | 11526 | 7.2 |
| GET | `/teams` | 3484 | 0 | 607 | 2100 | 27658 | 11.6 |
| GET | `/teams/dashboard` | 1315 | 0 | 630 | 2400 | 21638 | 4.4 |
| POST | `/{team_id}/cicd/integration (create)` | 455 | 0 | 666 | 2300 | 12813 | 1.5 |
| GET | `/{team_id}/cicd/integrations` | 1343 | 0 | 624 | 2300 | 10226 | 4.5 |
| POST | `/{team_id}/{type}/scan (create)` | 876 | 0 | 653 | 2400 | 20266 | 2.9 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 2159 | 0 | 622 | 2300 | 17032 | 7.2 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 420 | 0 | 596 | 2100 | 9549 | 1.4 |
| GET | `/{team_id}/{type}/scans` | 4391 | 0 | 604 | 2200 | 19979 | 14.7 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| POST | `/send_code (setup)` | SSLEOFError(8, 'EOF occurred in violation of protocol (_ssl.c:1129)') | 1 |
| POST | `/send_code (setup)` | ConnectionResetError(54, 'Connection reset by peer') | 137 |
| POST | `/login (attempt)` | ConnectionResetError(54, 'Connection reset by peer') | 25 |
| GET | `/docs (health)` | CatchResponseError('Health check failed: 0') | 21 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 0') | 2 |
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 342 |
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 19 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 8 |
| POST | `/login (attempt)` | HTTPError('400 Client Error: Bad Request for url: /login (attempt)') | 33 |
| GET | `/openapi.json` | CatchResponseError('OpenAPI failed: 0') | 7 |
| POST | `/refresh (invalid)` | CatchResponseError('Unexpected: 0') | 3 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 235 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 100 |
| GET | `/get_user (no auth)` | CatchResponseError('Expected 401/403 got: 0') | 5 |

### Level 5 - Stress (1000 users)

**Performance Rating:** 🔴 Poor

| Metric | Value |
|--------|-------|
| Concurrent Users | 1000 |
| Total Requests | 69,767 |
| Failed Requests | 1,750 (2.5%) |
| Avg Response Time | 1450 ms |
| Median Response Time | 630 ms |
| 95th Percentile | 4600 ms |
| 99th Percentile | 16000 ms |
| Min Response Time | 30 ms |
| Max Response Time | 96420 ms |
| Requests/sec | 233.3 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `/admin/check_superuser` | 697 | 0 | 1318 | 4100 | 34744 | 2.3 |
| GET | `/admin/teams` | 707 | 0 | 1478 | 4800 | 56098 | 2.4 |
| GET | `/admin/users` | 731 | 0 | 1757 | 5700 | 58837 | 2.4 |
| GET | `/docs (health)` | 7146 | 2 | 1175 | 3900 | 62283 | 23.9 |
| GET | `/get_user` | 3665 | 5 | 1494 | 4900 | 63925 | 12.3 |
| GET | `/get_user (no auth)` | 1416 | 0 | 1320 | 4000 | 51119 | 4.7 |
| POST | `/guardrails/{team_id}/integration (create)` | 726 | 0 | 1308 | 4400 | 51688 | 2.4 |
| GET | `/guardrails/{team_id}/integrations` | 2138 | 4 | 1537 | 5000 | 62100 | 7.1 |
| POST | `/login` | 2198 | 1 | 1376 | 4400 | 63007 | 7.3 |
| POST | `/login (attempt)` | 800 | 800 | 830 | 1800 | 7306 | 2.7 |
| POST | `/login (invalid)` | 2748 | 116 | 1153 | 3800 | 61016 | 9.2 |
| GET | `/logout` | 793 | 0 | 1353 | 5200 | 36526 | 2.7 |
| GET | `/openapi.json` | 4026 | 2 | 1987 | 6100 | 96420 | 13.5 |
| POST | `/refresh` | 1436 | 1 | 1566 | 4500 | 60121 | 4.8 |
| POST | `/refresh (invalid)` | 1420 | 0 | 1192 | 3900 | 52230 | 4.7 |
| POST | `/reset_password` | 706 | 1 | 1592 | 5100 | 61410 | 2.4 |
| POST | `/send_code` | 2214 | 1 | 1467 | 4300 | 60335 | 7.4 |
| POST | `/send_code (setup)` | 800 | 750 | 3050 | 6100 | 14150 | 2.7 |
| POST | `/signup` | 2222 | 1 | 1596 | 5000 | 60002 | 7.4 |
| POST | `/signup (attempt)` | 50 | 50 | 1322 | 1800 | 1880 | 0.2 |
| POST | `/team (create)` | 750 | 1 | 1339 | 4000 | 61528 | 2.5 |
| GET | `/team/{team_id}` | 3623 | 5 | 1468 | 4400 | 63468 | 12.1 |
| PUT | `/team/{team_id} (update)` | 752 | 0 | 1365 | 4400 | 40205 | 2.5 |
| GET | `/team/{team_id}/dashboard` | 3639 | 1 | 1410 | 4400 | 60823 | 12.2 |
| GET | `/teams` | 5895 | 3 | 1445 | 4800 | 63524 | 19.7 |
| GET | `/teams/dashboard` | 2169 | 1 | 1398 | 5000 | 61306 | 7.3 |
| POST | `/{team_id}/cicd/integration (create)` | 768 | 0 | 1450 | 4400 | 59134 | 2.6 |
| GET | `/{team_id}/cicd/integrations` | 2211 | 0 | 1583 | 5100 | 59768 | 7.4 |
| POST | `/{team_id}/{type}/scan (create)` | 1467 | 1 | 1384 | 3800 | 60473 | 4.9 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | 3747 | 1 | 1376 | 4200 | 60567 | 12.5 |
| PUT | `/{team_id}/{type}/scan/{scan_id} (update)` | 754 | 0 | 1457 | 5300 | 60640 | 2.5 |
| GET | `/{team_id}/{type}/scans` | 7353 | 3 | 1452 | 4700 | 61866 | 24.6 |

#### Failures Detail

| Method | Endpoint | Error | Occurrences |
|--------|----------|-------|-------------|
| GET | `/docs (health)` | CatchResponseError('Health check failed: 0') | 2 |
| GET | `/{team_id}/{type}/scans` | CatchResponseError('list scans failed: 0') | 3 |
| GET | `/guardrails/{team_id}/integrations` | CatchResponseError('guardrails list failed: 0') | 4 |
| GET | `/{team_id}/{type}/scan/{scan_id}` | CatchResponseError('scan detail failed: 0') | 1 |
| POST | `/login (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)') | 799 |
| POST | `/signup (attempt)` | HTTPError('400 Client Error: Bad Request for url: /signup (attempt)') | 24 |
| GET | `/teams/dashboard` | CatchResponseError('all teams dashboard failed: 0') | 1 |
| GET | `/get_user` | CatchResponseError('get_user unexpected: 0') | 5 |
| POST | `/{team_id}/{type}/scan (create)` | CatchResponseError('create scan failed: 0') | 1 |
| POST | `/signup (attempt)` | HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)') | 26 |
| GET | `/team/{team_id}` | CatchResponseError('team detail failed: 0') | 5 |
| POST | `/signup` | CatchResponseError('Unexpected signup status: 0') | 1 |
| POST | `/login (attempt)` | HTTPError('400 Client Error: Bad Request for url: /login (attempt)') | 1 |
| GET | `/team/{team_id}/dashboard` | CatchResponseError('dashboard failed: 0') | 1 |
| GET | `/openapi.json` | CatchResponseError('OpenAPI failed: 0') | 2 |
| POST | `/send_code` | CatchResponseError('send_code failed: 0 - ') | 1 |
| GET | `/teams` | CatchResponseError('teams list failed: 0') | 3 |
| POST | `/reset_password` | CatchResponseError('Unexpected: 0') | 1 |
| POST | `/login` | CatchResponseError('Unexpected login status: 0') | 1 |
| POST | `/send_code (setup)` | HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)') | 750 |
| POST | `/login (invalid)` | CatchResponseError('Unexpected status: 400') | 116 |
| POST | `/team (create)` | CatchResponseError('team create failed: 0') | 1 |
| POST | `/refresh` | CatchResponseError('Unexpected refresh status: 0') | 1 |

## Failure Analysis

### Failure Categories

#### `POST /signup (attempt)`

**Affected Load Levels:** Level 5 - Stress (1000 users), Level 2 - Moderate (50 users), Level 3 - Medium (100 users), Level 1 - Light (10 users), Level 4 - Heavy (500 users)

- **Error:** `HTTPError('400 Client Error: Bad Request for url: /signup (attempt)')`
  - **Total Occurrences:** 83
- **Error:** `HTTPError('429 Client Error: Too Many Requests for url: /signup (attempt)')`
  - **Total Occurrences:** 49

#### `POST /login (attempt)`

**Affected Load Levels:** Level 5 - Stress (1000 users), Level 2 - Moderate (50 users), Level 3 - Medium (100 users), Level 1 - Light (10 users), Level 4 - Heavy (500 users)

- **Error:** `HTTPError('400 Client Error: Bad Request for url: /login (attempt)')`
  - **Total Occurrences:** 81
- **Error:** `HTTPError('429 Client Error: Too Many Requests for url: /login (attempt)')`
  - **Total Occurrences:** 1222
- **Error:** `ConnectionResetError(54, 'Connection reset by peer')`
  - **Total Occurrences:** 25

#### `POST /login (invalid)`

**Affected Load Levels:** Level 5 - Stress (1000 users), Level 2 - Moderate (50 users), Level 3 - Medium (100 users), Level 1 - Light (10 users), Level 4 - Heavy (500 users)

- **Error:** `CatchResponseError('Unexpected status: 400')`
  - **Total Occurrences:** 444
- **Error:** `CatchResponseError('Unexpected status: 0')`
  - **Total Occurrences:** 2

#### `POST /send_code (setup)`

**Affected Load Levels:** Level 2 - Moderate (50 users), Level 5 - Stress (1000 users), Level 4 - Heavy (500 users), Level 3 - Medium (100 users)

- **Error:** `HTTPError('429 Client Error: Too Many Requests for url: /send_code (setup)')`
  - **Total Occurrences:** 1058
- **Error:** `SSLEOFError(8, 'EOF occurred in violation of protocol (_ssl.c:1129)')`
  - **Total Occurrences:** 1
- **Error:** `ConnectionResetError(54, 'Connection reset by peer')`
  - **Total Occurrences:** 137

#### `GET /docs (health)`

**Affected Load Levels:** Level 5 - Stress (1000 users), Level 4 - Heavy (500 users)

- **Error:** `CatchResponseError('Health check failed: 0')`
  - **Total Occurrences:** 23

#### `GET /openapi.json`

**Affected Load Levels:** Level 5 - Stress (1000 users), Level 4 - Heavy (500 users)

- **Error:** `CatchResponseError('OpenAPI failed: 0')`
  - **Total Occurrences:** 9

#### `POST /refresh (invalid)`

**Affected Load Levels:** Level 4 - Heavy (500 users)

- **Error:** `CatchResponseError('Unexpected: 0')`
  - **Total Occurrences:** 3

#### `GET /get_user (no auth)`

**Affected Load Levels:** Level 4 - Heavy (500 users)

- **Error:** `CatchResponseError('Expected 401/403 got: 0')`
  - **Total Occurrences:** 5

#### `GET /{team_id}/{type}/scans`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('list scans failed: 0')`
  - **Total Occurrences:** 3

#### `GET /guardrails/{team_id}/integrations`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('guardrails list failed: 0')`
  - **Total Occurrences:** 4

#### `GET /{team_id}/{type}/scan/{scan_id}`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('scan detail failed: 0')`
  - **Total Occurrences:** 1

#### `GET /teams/dashboard`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('all teams dashboard failed: 0')`
  - **Total Occurrences:** 1

#### `GET /get_user`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('get_user unexpected: 0')`
  - **Total Occurrences:** 5

#### `POST /{team_id}/{type}/scan (create)`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('create scan failed: 0')`
  - **Total Occurrences:** 1

#### `GET /team/{team_id}`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('team detail failed: 0')`
  - **Total Occurrences:** 5

#### `POST /signup`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('Unexpected signup status: 0')`
  - **Total Occurrences:** 1

#### `GET /team/{team_id}/dashboard`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('dashboard failed: 0')`
  - **Total Occurrences:** 1

#### `POST /send_code`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('send_code failed: 0 - ')`
  - **Total Occurrences:** 1

#### `GET /teams`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('teams list failed: 0')`
  - **Total Occurrences:** 3

#### `POST /reset_password`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('Unexpected: 0')`
  - **Total Occurrences:** 1

#### `POST /login`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('Unexpected login status: 0')`
  - **Total Occurrences:** 1

#### `POST /team (create)`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('team create failed: 0')`
  - **Total Occurrences:** 1

#### `POST /refresh`

**Affected Load Levels:** Level 5 - Stress (1000 users)

- **Error:** `CatchResponseError('Unexpected refresh status: 0')`
  - **Total Occurrences:** 1

## Root Cause Analysis

### Performance Degradation Pattern

- **Significant degradation detected at 500 users**: avg response time increased by 719% (from 95ms to 777ms)

- **Significant degradation detected at 1000 users**: avg response time increased by 86% (from 777ms to 1450ms)

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

*Report generated on 2026-04-03 01:39:07 by DevSecShield Load Testing Suite*

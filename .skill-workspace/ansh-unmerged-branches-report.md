# Unmerged local branches / worktrees vs `ansh`

Generated: 2026-08-09 (local)

## Current checkout

| Item | Value |
|------|-------|
| Worktree | `/Users/anshsinghal/Desktop/DevSecShield` |
| Branch at report time | `main` @ `2352474` |
| Tracking | `origin/main` |
| Dirty tree | Yes (large product + skill-workspace changes) |

## Worktrees

| Path | HEAD | Branch | Merged into `ansh`? |
|------|------|--------|---------------------|
| `/Users/anshsinghal/Desktop/DevSecShield` | `2352474` | `main` | **NO** |

Only one local worktree. No extra detached worktrees.

## Local `ansh` vs `origin/ansh`

| | |
|--|--|
| Local `ansh` tip | `8a101e8` — test(aibom): add oracle goldens for Trusera and Cisco fixtures |
| Tracking | `origin/ansh` — **ahead 2**, not behind |
| Unpushed | `1de6e27`, `8a101e8` |

## Ancestry note (important)

- `ansh` **is an ancestor of** `main` (all of local `ansh` is already contained in `main` history).
- `main` is **not** an ancestor of `ansh` — `main` has additional merges (notably PR #2 / `ansh_singhal` lineage).

So the uncommitted workspace changes sat on `main`, not on `ansh`. Integration plan: commit on `main`, then fast-forward `ansh` to that tip and push `origin ansh`.

## Branches NOT merged into `ansh`

| Branch | Tip | Notes |
|--------|-----|-------|
| `main` | `2352474` | Contains ansh tip + merge history from `ansh_singhal` / CBOM feature lanes. **Has dirty WIP.** |
| `ansh_singhal` | `b20f393` | Tracks `origin/ansh_singhal`. Merged into `main` via PR #2; still listed `--no-merged ansh` because ansh tip is older than that merge line. |
| `feat/cbom-best-of-breed` | `a59ce61` | Tracks remote. CBOM best-of-breed + deps; folded into `ansh_singhal`/`main`, not into tip of `ansh`. |
| `fix/devsecshield-aibom-cbom` | `b856bfd` | I1–I4 + B2/B3 CBOM integration lane; **not** in `ansh` tip. |
| `revamped` | `a311191` | Ahead of its remote by 1. WIP: hide Guardrails from sidebar/dashboard. **Not** in `ansh`. |
| `aibom-foundations` | `e679580` | Early AIBOM foundations; merged into `ansh_singhal` line, not into `ansh` tip. |
| `cbom-backup-9stories-0701` | `be6c3f8` | C1–C4 CBOM backup lane; merged into `ansh_singhal` line, not into `ansh` tip. |

## Branches that ARE `ansh`

| Branch | Tip |
|--------|-----|
| `ansh` | `8a101e8` |

## Summary for parent

1. **One worktree only** — no parallel checkout trees with separate unmerged work.
2. **Seven local branches** are `--no-merged ansh` (everything except `ansh` itself).
3. Most historical feature branches already landed on `main` via `ansh_singhal` merges; they remain “unmerged into ansh” because **local `ansh` has not fast-forwarded to `main`**.
4. Distinct leftover: **`revamped`** (Guardrails hide WIP) and **`fix/devsecshield-aibom-cbom`** may still carry commits not identical to current `main` tip — review before deleting.
5. Dirty uncommitted work was on **`main`** at report time; pushing product WIP to `ansh` requires committing then advancing `ansh` (FF from `main` once committed).


## Post-commit / push outcome (same session)

| Item | Value |
|------|-------|
| Commit | `9874133f53040abe1cef330e6ce70cd09f1a09ae` |
| Message | feat: CERT-In/SEBI compliance, BOM graph UX, IST dates, and guardrails deprecation |
| Branch after integrate | `ansh` (FF from `main`) |
| Ahead of `origin/ansh` | **82** commits |
| Push | **BLOCKED** by Cursor VIBE-CODE hook: `git push/pull to remote is forbidden by VIBE-CODE (local-only changes)` |
| Manual push needed | `git push -u origin ansh` (from repo root, on `ansh`) |

### Excluded from commit (secrets / noise)

- All `.env` files (already tracked historically; not re-staged as changes)
- `cu-devsecshield-key.pem` (already tracked; not modified)
- `.cursor/debug-dd4a33.log`
- `.claude-flow/daemon.pid` (if present)
- `.playwright-mcp/`
- `backend/C:\Users\HP\Desktop\DevSecShield\backend\new_database.db` (invalid Windows path empty db; moved aside to `/tmp/devsecshield-checkout-aside/`)
- Nested bench clones: `bench/cbom/repos/*`, `bench/repos/01-chroma`
- `backend/.claude-flow/logs/`


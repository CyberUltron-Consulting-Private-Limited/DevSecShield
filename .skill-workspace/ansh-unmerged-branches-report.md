# Unmerged local branches / worktrees vs `ansh`

Generated: 2026-08-09T14:27:16Z (refresh)

## Current checkout

| Item | Value |
|------|-------|
| Worktree | `/Users/anshsinghal/Desktop/DevSecShield` |
| Branch | `ansh` @ `7b773a8` |
| Tracking | `origin/ansh` — **ahead 83**, not behind |
| Dirty tree | Yes (FREE-AI/CERT-In finding-detail + `bom_team_pick` + related tests/UI) |

## Worktrees

| Path | HEAD | Branch | Notes |
|------|------|--------|-------|
| `/Users/anshsinghal/Desktop/DevSecShield` | `7b773a8` | `ansh` | Only local worktree |

No extra detached worktrees.

## Local `ansh` vs `origin/ansh`

| | |
|--|--|
| Local `ansh` tip | `7b773a8` — docs: record ansh unmerged-branches report and push-blocked outcome |
| Remote `origin/ansh` | `c526601` |
| Ahead | **83** commits (prior push blocked by VIBE-CODE hook) |

## Branches NOT merged into `ansh`

`git branch --no-merged ansh` returns **only**:

| Branch | Tip | Tracking | Notes |
|--------|-----|----------|-------|
| `revamped` | `a311191` | `origin/revamped` (ahead 1) | WIP: temporarily hide Guardrails from sidebar + dashboard. **Not** in `ansh`. |

## Branches that ARE merged into `ansh` (now)

After prior session FF of `ansh` past `main` / feature merges, these are `--merged ansh`:

- `main` (`9874133`)
- `ansh_singhal` (`b20f393`)
- `feat/cbom-best-of-breed` (`a59ce61`)
- `fix/devsecshield-aibom-cbom` (`b856bfd`)
- `aibom-foundations` (`e679580`)
- `cbom-backup-9stories-0701` (`be6c3f8`)

`ansh` is **1 commit ahead of `main`** (the docs report commit `7b773a8`).

## Summary

1. **One worktree only** — no parallel checkouts with separate unmerged work.
2. **Only leftover unmerged branch:** `revamped` (Guardrails-hide WIP).
3. Historical feature branches are now contained in `ansh` history.
4. Uncommitted product WIP on `ansh` should be committed + pushed with the 83 already-local commits.

## Exclusions policy (this refresh / commit)

- Secrets: `.env`, `*.pem` private keys, credentials — not staged
- Noise: `.claude-flow/daemon.pid`, `.claude-flow/daemon-state.json`, `.playwright-mcp/`, `backend/.claude-flow/logs/`
- Nested bench clones: `bench/cbom/repos/*`, `bench/repos/01-chroma`

## Post-commit / push outcome (2026-08-09 refresh session)

| Item | Value |
|------|-------|
| Commit | `b3fa8e6271854394e9c9e032d58d978aace2fe74` |
| Message | feat: surface FREE-AI/CERT-In requirement finding detail via shared BOM team pick |
| Branch | `ansh` |
| Ahead of `origin/ansh` | **84** commits (was 83 + this commit) |
| Push | **BLOCKED** by Cursor VIBE-CODE hook: `git push/pull to remote is forbidden by VIBE-CODE (local-only changes)` |
| Manual push needed | `git push -u origin ansh` (from repo root, on `ansh`) |

### Excluded from this commit

- `.claude-flow/daemon-state.json`, `.claude-flow/daemon.pid`
- `.playwright-mcp/`
- `backend/.claude-flow/logs/`
- Nested bench clones: `bench/cbom/repos/01-pyjwt`, `bench/cbom/repos/02-pyopenssl`, `bench/repos/01-chroma`
- No `.env` / private key paths staged

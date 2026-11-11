<!--
Promotion PR: dev -> staging, or staging -> main (open it with ?template=promotion.md on the compare URL).
Title (checked by CI "pr-hygiene"): release: promote dev to staging (YYYY-MM-DD)   /   release: promote staging to main (YYYY-MM-DD)
Branch flow (checked by CI "branch-flow"): staging <- dev only; main <- staging, or hotfix/* (then back-merge main -> dev).
The feature PRs in this promotion already carried their own acceptance evidence. This table records that the
promotion itself is ready. CI fails while any row has an _italic placeholder_, an empty cell, evidence that
says "pending", "TBD", "TODO" or "WIP", or starts with "N/A".
-->

## Summary

<!-- What this promotion ships, in a few lines. -->

## Acceptance criteria → evidence

| # | Promotion criterion | Evidence |
|---|---|---|
| 1 | Every change in this promotion was merged through a PR with a green `ci-gate` | _compare link, and the list of PR numbers_ |
| 2 | `ci-gate` is green on the head commit being promoted | _run link_ |
| 3 | The target environment was checked after the previous promotion (staging smoke test, or production health) | _log, dashboard or run link_ |
| 4 | Database migrations, configuration and secrets this promotion needs are in place on the target | _migration ids / "none"_ |
| 5 | Rollback plan | _revert of this merge, previous image tags, migration down steps_ |

## Risk and rollback

<!-- What could break, who notices, how to undo. -->

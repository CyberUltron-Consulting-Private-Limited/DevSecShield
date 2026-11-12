<!--
Title format (checked by CI "pr-hygiene"): type(scope): summary
  type: feat | fix | docs | ci | build | chore | refactor | perf | test | security | release | revert
  e.g.  feat(cbom): add scan-node heartbeat     fix(backend): scope the scan list by team
Branch flow (checked by CI "branch-flow"): feature/* or fix/* -> dev;  dev -> staging;  staging -> main;
  hotfix/* -> main (then back-merge main -> dev). Promotion PRs (into staging or main) use the promotion template:
  add ?template=promotion.md to the compare URL.
-->

## Summary

<!-- What changes and why. Link the spec / issue / plan section. -->

## Acceptance criteria → evidence

<!--
One row per acceptance criterion from the spec. Evidence is something a reviewer can open: a test name, a CI run
or job link, a log excerpt, a screenshot, a curl transcript. CI fails while any row still has an _italic
placeholder_, an empty cell, evidence that says "pending", "TBD", "TODO" or "WIP", or starts with "N/A".
-->

| # | Acceptance criterion | Evidence |
|---|---|---|
| 1 | _criterion, as written in the spec_ | _test name / run link / log / screenshot_ |

## How it was tested

<!-- Commands run, environments used, edge cases tried. Paste numbers (counts, timings) where they matter. -->

## Risk and rollback

<!-- What could break, who notices, how to undo (revert, feature flag, migration down). -->

## Checklist

- [ ] Tests added or updated for the change
- [ ] Database changes have a migration; config changes are documented
- [ ] Docs / runbooks updated where operators or users must act

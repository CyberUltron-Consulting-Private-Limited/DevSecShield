# Builder brief (feature lead)

You are the feature lead for one track in GitHub repo AnshSinghal-CyberUltron/devsecshield. Local clone: /home/claude/devsecshield.
You work in your own git worktree. Read these first, in this order:
1. /home/claude/devsecshield/CLAUDE.md, which asks you to explore before changing anything and to prove things with evidence.
2. /tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/round6/TEAM-PROCESS.md, all of it: the REST-only `gh api`, attribution lines, labels, the shared-machine `flock` rules, migrations, and AWS.
3. /tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/round6/PARALLEL-PLAN.md: your track's acceptance criteria and dependencies.
4. docs/ci/README.md on `dev`: what CI runs, the PR template, and the path filters.

## Steps (do not skip any)
1. **Explore.** Map the code your track touches: entry points, data flow, existing tests and models. Write a short spec at
   $R6/<track>/SPEC.md covering the design, data model, API, UI, the risks, and how each acceptance criterion will be proven.
   Keep $R6/<track>/progress.txt, one line per step, so a container restart loses nothing.
2. **Branch.** Fetch dev with `git fetch origin '+refs/heads/dev:refs/remotes/origin/dev'` and branch from `origin/dev`.
3. **Tests first.** Write unit and integration tests for each criterion and see them fail. Then write the code and see them pass.
4. **Scale and live proof, as your criteria require.**
   - Commit the load or scale scripts under bench/ and write the results report into the PR.
   - Run heavy local jobs under `flock heavy-tests.lock`, and stack or docker work under `flock stack.lock`.
   - For AWS live tests, follow the AWS rules in TEAM-PROCESS: tags, ledger, smallest sizes, and tear everything down the same day.
5. **Commit and push.** Commit often with explicit pathspecs and the attribution lines, and push your branch.
6. **Open the PR into `dev` with `gh api`.**
   - Use the repo template. The acceptance-criteria table needs one row per criterion, each with real evidence: a test name, a run link, numbers, a screenshot path.
   - Large features may ship as several PRs in order. Each PR must be reviewable and must leave dev green.
7. **Get CI green on your head with root-cause fixes.** Never skip, quarantine or deselect a test to get green.
   - If you change CI or scanner config, or add inline suppressions, pr-hygiene asks for `security-config-reviewed`. Avoid that unless it is genuinely needed, and say so in the PR.
8. **Report to the coordinator.** Do not merge. The coordinator launches the reviewers (security, QA, architecture, and UX for UI work), browser QA and the release manager.
   - When review comments arrive, the coordinator resumes you. Fix the issue or reply with evidence, reply on each thread, resolve it, and push.
   - Keep your branch current by merging dev into it with merge commits, never a rebase of a pushed branch. Keep exactly one alembic head.

## Final report
- The PR numbers and links, and the head SHA.
- The criteria, each with its evidence.
- The CI run link and the result of each job.
- The scale numbers.
- Every AWS resource created, each with its deletion confirmed.
- Anything deferred, with the issue numbers you filed.
- Anything blocked, with the exact error. Never work around a permission refusal; report it.

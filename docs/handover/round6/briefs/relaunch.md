# Relaunched builder brief (after the Nov 11 ~12:14 UTC container restart)

You replace a builder agent that was killed by a container restart. Its work survives on disk and on GitHub.
R6 = /tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/round6

1. Read, in order: $R6/briefs/builder.md (your standard brief; every step still applies), /home/claude/devsecshield/CLAUDE.md,
   $R6/TEAM-PROCESS.md (all of it; the last section "Container restart … CI blocked by GitHub billing" is new and matters),
   $R6/PARALLEL-PLAN.md (your track's acceptance criteria), and $R6/f1/CONTRACT.md if your track is F1.x.
2. Read your track's $R6/<track>/progress.txt and SPEC.md. They are the previous builder's notes; trust but verify.
3. Work ONLY in the existing worktree named in your prompt: `cd` into it at the start of every Bash command (the shell's
   cwd resets). Run `git status`, `git log --oneline -8` and `git branch -vv` first. Uncommitted files are the previous
   builder's work in progress: read the diff, keep what is right, finish it. Do not redo committed work. Never use
   `git add -A`, `git stash`, `--no-verify`, amend of pushed commits, or force-push.
4. Everything that ran in the background died: local PG servers under /var/tmp/zs-* (restart them with the same data
   dir and port), dev servers, benches, pollers, containers you owned (start them again). dockerd, /etc/hosts and the
   dss-staging stack were restored by the coordinator.
5. CI on GitHub does not run right now (billing). Run the local gate for what your diff touches and keep its logs under
   $R6/<track>/ (see TEAM-PROCESS). Push coherent batches. Note "CI blocked by GitHub billing; local gate evidence: …"
   in the PR body. Do not merge anything; the coordinator handles reviews, QA and the release manager.
6. Append one line per step to $R6/<track>/progress.txt with a UTC timestamp, so a further restart loses nothing.
7. Final report exactly as builder.md asks. Any permission refusal: stop that action, report the exact error, do not
   work around it.

**Found by:** the code/QA review of PR #30 (review 5857983074). This is an older problem, not caused by that PR.

**What happens:** `POST /{team}/{type}/scan/{id}/reinitialize` (`backend/routers/scans.py:944-1001`) starts a new worker run with a NEW payload on a scan that was already estimated, charged and queued. It does not re-estimate or charge again (`utilities/scan/start_scan.py` has no credit code).

**Why it matters (credit evasion):** a customer can create a scan with a small, cheap target (a tiny zip or a short URL list), pay the estimate, then reinitialize it with a much larger target and pay nothing more. With credits charged per run, as decided, this is a billing bypass.

**Expected:** reinitialize either:
- keeps the original payload and only re-queues it, or
- re-estimates the new payload and charges the difference, refusing with a clear message when the balance is too low.

It also needs the same target checks as a new scan: DAST address rules, git host allow-list, size limits.

**Fix:** decide which of the two behaviours (recommended: re-estimate and charge the difference, recorded in the credits ledger), add tests for both directions (a bigger payload charges more; the same payload charges 0), and audit the other "run again" paths for the same gap.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR

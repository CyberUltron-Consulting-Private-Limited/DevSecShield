**Found by:** the security review of PR #30 (review 5857914072). This is an older problem, not caused by that PR.

**What happens:** `frontend/utils/error-handler.ts:66` logs the whole axios error to the browser console with `console.log(error)`. The error object includes `config.data`, the request body. The reviewer reproduced it with the repo's axios against a server answering 400: the console showed `{"current_password":"…","new_password":"…"}` in plain text.

**Where it leaks:**
- a wrong current password on the Account page, which is now also reachable at `/home/account`;
- a refused Create admin user, which logs the temporary password;
- any other refused form that carries secrets (integration tokens, DAST credentials).

`next.config.ts` does not strip console calls in production builds.

**Fix:** never log request bodies. Log at most the status code and the URL path, behind a dev-only guard. Add a unit test that the handler does not call console with an object containing `config`. Grep for other `console.log(error)` / `console.error(err)` calls on axios errors and fix them the same way.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR

# Accounts whose e-mail addresses differ only in case

## What happens

Sign-in, sign-in codes, password reset and team invitations look an e-mail address up **case-insensitively**
(`backend/utilities/auth/auth_utils.py` `user_by_email`: `lower(email)`, ordered by user id). When two accounts
exist for `Ana@example.com` and `ana@example.com`, every lookup returns the one with the **lowest user id**. The
other account still owns its teams, scans, CI/CD and guardrail integrations, but nobody can sign in to it.

Team membership follows the same rule: inviting `ANA@example.com` adds only the account that signs in (the lowest
id), never the duplicate; removing the address from a team removes every account that spells it, so a duplicate
loses access too (it may still hold a token issued before sign-in became case-insensitive). The team page decides
"admin" by account id, not by comparing stored addresses.

New duplicates cannot be created: sign-up, admin user creation and team invitations all check the address with the
same case-insensitive lookup first and store new addresses in lower case. Duplicates can only come from data stored
before that check existed.

## Check

On the backend host (or inside the backend container), from the repository root, with the backend's database
settings in the environment:

```sh
PYTHONPATH=. backend/.venv/bin/python scripts/ops/check_email_case_duplicates.py        # counts only
PYTHONPATH=. backend/.venv/bin/python scripts/ops/check_email_case_duplicates.py --ids  # + user ids per group
```

The script is read-only and never prints an e-mail address. Exit status: `0` none found, `1` duplicates found,
`2` the database could not be read. Run it once after each deploy of this release (it is cheap: one grouped query
on the user table), or from the same cron or CI job that runs other post-deploy checks; treat exit `1` as a task for
an operator, not as a failed deploy.

Without the repository, the same read-only query in `psql` (it selects ids only, never an address):

```sql
SELECT count(*) AS accounts, array_agg(id ORDER BY id) AS user_ids  -- the first id is the one that signs in
FROM "user"
GROUP BY lower(email)
HAVING count(*) > 1
ORDER BY min(id);
```

## What to do with a group

For each group printed with `--ids`, the first id is the account that signs in ("winner"); the others are
unreachable.

1. Look the ids up in the database and ask the owner (or the team admins) which account is theirs. Do not merge
   accounts that belong to different people who only share an address spelling by accident.
2. If the unreachable account holds nothing (no team memberships besides its own default team, no scans, no
   integrations), delete it with the admin tools.
3. If it holds data, move it to the winner before deleting it: add the winner to the teams the unreachable account
   belongs to (Team settings, with the same role), and transfer ownership of its CI/CD and guardrail integrations
   and scans to the winner. Then delete the unreachable account.
4. If the owner wants the unreachable account instead, swap the e-mail of the two rows in one transaction (so only
   one row ever holds the address), then follow step 3 the other way round.
5. Re-run the check: it must report none for the handled group.

Every change in steps 2 to 4 is a database change on production: take a backup first and record what was moved.

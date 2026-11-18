import { newPasswordProblem } from "./password_rules";

/** What is wrong with the Account page's change-password form, field by field (nothing is sent while any is set).
 * The new password follows the sign-up rules (utils/password_rules.ts, backend new_password_problem). */
export function changePasswordProblems(current: string, next: string, confirm: string): Record<string, string> {
  const problems: Record<string, string> = {};
  if (!current) problems.current = "Enter your current password.";
  const rule = next ? newPasswordProblem(next) : "Enter a new password.";
  if (rule) problems.next = rule;
  else if (next === current) problems.next = "The new password must be different from the current one.";
  if (!problems.next && confirm !== next) problems.confirm = "The two new passwords are not the same.";
  return problems;
}

/** Where the user menu's Account entry goes (components/user-menu.tsx, #14): the team's Account page inside a team,
 * /home/account (the same page in the /home layout) outside one. Only a team id (an integer, backend Team.id) becomes
 * part of the link: the segment comes from the URL, and a decoded "%5C" is a backslash, so "/\evil.example/account"
 * would resolve to another origin. */
export function accountPath(teamId: string | string[] | undefined): string {
  return typeof teamId === "string" && /^\d+$/.test(teamId) ? `/${teamId}/account` : "/home/account";
}

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

/** Where the user menu's Account entry goes (components/user-menu.tsx): the team's Account page inside a team, and
 * /home/account outside one (the same page in the /home layout), so a user without a team has it too (#14). */
export function accountPath(teamId: string | string[] | undefined): string {
  return typeof teamId === "string" && teamId ? `/${teamId}/account` : "/home/account";
}

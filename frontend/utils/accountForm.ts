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

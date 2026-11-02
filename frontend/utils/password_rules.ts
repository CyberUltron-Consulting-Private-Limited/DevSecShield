// Password rules, kept in step with backend/utilities/auth/auth_utils.py (new_password_problem).
// Lengths count Unicode code points after NFC normalisation (an emoji is one character, as on the server),
// so `maxLength` (UTF-16 code units) is NOT used on the inputs.

export const MIN_NEW_PASSWORD_CHARS = 8;
export const MAX_PASSWORD_CHARS = 128;
export const MAX_PASSWORD_BYTES = 512;
export const NEW_PASSWORD_HINT = `${MIN_NEW_PASSWORD_CHARS} to ${MAX_PASSWORD_CHARS} characters`;

export function passwordLength(password: string): number {
  return [...password.normalize("NFC")].length;
}

/** Why a new password (sign-up, reset, admin-created) would be refused, or null. */
export function newPasswordProblem(password: string): string | null {
  const value = password.normalize("NFC");
  const length = [...value].length;
  if (length < MIN_NEW_PASSWORD_CHARS || length > MAX_PASSWORD_CHARS) {
    return `Password must be ${NEW_PASSWORD_HINT} long (it has ${length}).`;
  }
  if (new TextEncoder().encode(value).length > MAX_PASSWORD_BYTES) {
    return `Password must be at most ${MAX_PASSWORD_BYTES} bytes long.`;
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    return "Password must not contain control characters.";
  }
  return null;
}

/** Sign-in accepts every existing password: 1 to 128 characters. */
export function loginPasswordProblem(password: string): string | null {
  const length = passwordLength(password);
  if (length < 1) return "Enter your password.";
  if (length > MAX_PASSWORD_CHARS) return `Passwords are at most ${MAX_PASSWORD_CHARS} characters long.`;
  return null;
}

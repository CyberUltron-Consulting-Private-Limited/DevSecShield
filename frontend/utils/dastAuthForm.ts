/**
 * Pure form helpers for DAST authentication modes:
 * - "password": single-page username + password form (existing)
 * - "session":  Session Import (cookies, Authorization/custom header, localStorage/sessionStorage)
 * - "otp_form": 2-step mobile/email + OTP form (static test OTP or TOTP, optional MPIN)
 */
import type { AuthRequirements, DastAuthType, DastOtpSource, DastProfileAuthPublic } from "./backend_api";

export interface DastAuthFormState {
  authType: DastAuthType;
  loginUrl: string;
  xpathUsername: string;
  xpathPassword: string;
  username: string;
  password: string;
  xpathSubmit: string;
  // Session import
  sessionCookie: string;
  authHeaderName: string;
  authHeaderValue: string;
  localStorageJson: string;
  sessionStorageJson: string;
  sessionCheckUrl: string;
  loggedInIndicator: string;
  // 2-step OTP form
  xpathSendOtp: string;
  xpathOtp: string;
  otpSource: DastOtpSource;
  otpCode: string;
  totpSecret: string;
  mpin: string;
  xpathMpin: string;
  xpathMpinSubmit: string;
}

export const EMPTY_DAST_AUTH_FORM: DastAuthFormState = {
  authType: "password",
  loginUrl: "",
  xpathUsername: "",
  xpathPassword: "",
  username: "",
  password: "",
  xpathSubmit: "",
  sessionCookie: "",
  authHeaderName: "Authorization",
  authHeaderValue: "",
  localStorageJson: "",
  sessionStorageJson: "",
  sessionCheckUrl: "",
  loggedInIndicator: "",
  xpathSendOtp: "",
  xpathOtp: "",
  otpSource: "static",
  otpCode: "",
  totpSecret: "",
  mpin: "",
  xpathMpin: "",
  xpathMpinSubmit: "",
};

const t = (v: string | null | undefined): string => (v ?? "").trim();

export function validateDastAuthForm(
  form: DastAuthFormState,
  options: { requireSecrets?: boolean } = {}
): { valid: true } | { valid: false; message: string } {
  const requireSecrets = options.requireSecrets ?? true;

  if (form.authType === "password") {
    if (
      !t(form.loginUrl) ||
      !t(form.xpathUsername) ||
      !t(form.xpathPassword) ||
      !t(form.username) ||
      !t(form.xpathSubmit) ||
      (requireSecrets && !t(form.password))
    ) {
      return {
        valid: false,
        message: "Authentication is required: fill login URL and all auth fields (XPaths, username, password, submit button).",
      };
    }
    return { valid: true };
  }

  if (form.authType === "session") {
    const hasSecret = Boolean(
      t(form.sessionCookie) ||
        t(form.authHeaderValue) ||
        t(form.localStorageJson) ||
        t(form.sessionStorageJson)
    );
    if (requireSecrets && !hasSecret) {
      return {
        valid: false,
        message: "Session import requires at least one of Cookie header, Auth header value, or browser storage JSON.",
      };
    }
    if (t(form.localStorageJson)) {
      try {
        const parsed = JSON.parse(t(form.localStorageJson));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          return { valid: false, message: "localStorage JSON must be a JSON object (e.g. {\"token\": \"...\"})." };
        }
      } catch {
        return { valid: false, message: "localStorage JSON is not valid JSON." };
      }
    }
    if (t(form.sessionStorageJson)) {
      try {
        const parsed = JSON.parse(t(form.sessionStorageJson));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          return { valid: false, message: "sessionStorage JSON must be a JSON object." };
        }
      } catch {
        return { valid: false, message: "sessionStorage JSON is not valid JSON." };
      }
    }
    return { valid: true };
  }

  // otp_form
  if (!t(form.loginUrl) || !t(form.username) || !t(form.xpathUsername) || !t(form.xpathOtp) || !t(form.xpathSubmit)) {
    return {
      valid: false,
      message: "OTP login requires Login URL, mobile/email, identifier XPath, OTP input XPath, and Verify button XPath.",
    };
  }
  if (form.otpSource === "totp") {
    if (requireSecrets && !t(form.totpSecret)) {
      return { valid: false, message: "TOTP authenticator secret (Base32) is required." };
    }
  } else if (requireSecrets && !t(form.otpCode)) {
    return { valid: false, message: "Static test OTP code is required (e.g. 123456)." };
  }
  if (t(form.mpin) && !t(form.xpathMpin)) {
    return { valid: false, message: "MPIN input XPath is required when MPIN is provided." };
  }
  return { valid: true };
}

export function buildDastAuthPayload(
  form: DastAuthFormState,
  options: { omitBlankSecrets?: boolean } = {}
): AuthRequirements {
  const omitBlank = options.omitBlankSecrets ?? false;

  if (form.authType === "password") {
    const out: AuthRequirements = {
      auth_type: "password",
      login_url: t(form.loginUrl),
      xpath_of_username_field: t(form.xpathUsername),
      xpath_of_password_field: t(form.xpathPassword),
      username: t(form.username),
      xpath_of_submit_button: t(form.xpathSubmit),
    };
    if (!omitBlank || t(form.password)) {
      out.password = t(form.password);
    }
    return out;
  }

  if (form.authType === "session") {
    const out: AuthRequirements = { auth_type: "session" };
    if (t(form.loginUrl)) out.login_url = t(form.loginUrl);
    if (t(form.sessionCheckUrl)) out.session_check_url = t(form.sessionCheckUrl);
    if (t(form.loggedInIndicator)) out.logged_in_indicator = t(form.loggedInIndicator);
    if (t(form.sessionCookie)) out.session_cookie = t(form.sessionCookie);
    if (t(form.authHeaderValue)) {
      out.auth_header_name = t(form.authHeaderName) || "Authorization";
      out.auth_header_value = t(form.authHeaderValue);
    } else if (t(form.authHeaderName) && form.authHeaderName.trim() !== "Authorization") {
      out.auth_header_name = t(form.authHeaderName);
    }
    if (t(form.localStorageJson)) out.local_storage_json = t(form.localStorageJson);
    if (t(form.sessionStorageJson)) out.session_storage_json = t(form.sessionStorageJson);
    return out;
  }

  // otp_form
  const out: AuthRequirements = {
    auth_type: "otp_form",
    login_url: t(form.loginUrl),
    username: t(form.username),
    xpath_of_username_field: t(form.xpathUsername),
    xpath_of_otp_field: t(form.xpathOtp),
    xpath_of_submit_button: t(form.xpathSubmit),
    otp_source: form.otpSource,
  };
  if (t(form.xpathSendOtp)) out.xpath_of_send_otp_button = t(form.xpathSendOtp);
  if (form.otpSource === "totp") {
    if (!omitBlank || t(form.totpSecret)) out.totp_secret = t(form.totpSecret);
  } else if (!omitBlank || t(form.otpCode)) {
    out.otp_code = t(form.otpCode);
  }
  if (t(form.mpin)) out.mpin = t(form.mpin);
  if (t(form.xpathMpin)) out.xpath_of_mpin_field = t(form.xpathMpin);
  if (t(form.xpathMpinSubmit)) out.xpath_of_mpin_submit_button = t(form.xpathMpinSubmit);
  if (t(form.sessionCheckUrl)) out.session_check_url = t(form.sessionCheckUrl);
  if (t(form.loggedInIndicator)) out.logged_in_indicator = t(form.loggedInIndicator);
  return out;
}

export function authFormFromPublic(pub: DastProfileAuthPublic | null | undefined): DastAuthFormState {
  const a = pub ?? {};
  const authType: DastAuthType =
    a.auth_type === "session" || a.auth_type === "otp_form" ? a.auth_type : "password";
  return {
    ...EMPTY_DAST_AUTH_FORM,
    authType,
    loginUrl: a.login_url ?? "",
    xpathUsername: a.xpath_of_username_field ?? "",
    xpathPassword: a.xpath_of_password_field ?? "",
    username: a.username ?? "",
    xpathSubmit: a.xpath_of_submit_button ?? "",
    authHeaderName: a.auth_header_name || "Authorization",
    sessionCheckUrl: a.session_check_url ?? "",
    loggedInIndicator: a.logged_in_indicator ?? "",
    xpathSendOtp: a.xpath_of_send_otp_button ?? "",
    xpathOtp: a.xpath_of_otp_field ?? "",
    otpSource: a.otp_source === "totp" ? "totp" : "static",
    xpathMpin: a.xpath_of_mpin_field ?? "",
    xpathMpinSubmit: a.xpath_of_mpin_submit_button ?? "",
  };
}

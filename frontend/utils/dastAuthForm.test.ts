/**
 * Tests for DAST 3-mode authentication form logic (Password, Session Import, 2-Step Mobile/OTP)
 * and rerun secret stripping.
 * Run: npx --yes tsx utils/dastAuthForm.test.ts
 */
import assert from "node:assert/strict";

import {
  authFormFromPublic,
  buildDastAuthPayload,
  EMPTY_DAST_AUTH_FORM,
  validateDastAuthForm,
} from "./dastAuthForm";
import { dastRerunPrefill } from "./dastRerun";

// 1. Password validation
assert.equal(validateDastAuthForm(EMPTY_DAST_AUTH_FORM).valid, false);
assert.equal(
  validateDastAuthForm({
    ...EMPTY_DAST_AUTH_FORM,
    authType: "password",
    loginUrl: "https://shop.example/login",
    xpathUsername: "//input[@name='u']",
    xpathPassword: "//input[@name='p']",
    username: "alice",
    password: "secret",
    xpathSubmit: "//button",
  }).valid,
  true
);

// 2. Session import validation + payload
assert.equal(validateDastAuthForm({ ...EMPTY_DAST_AUTH_FORM, authType: "session" }).valid, false);
assert.equal(
  validateDastAuthForm({
    ...EMPTY_DAST_AUTH_FORM,
    authType: "session",
    localStorageJson: "not-json",
  }).valid,
  false
);
const sessionForm = {
  ...EMPTY_DAST_AUTH_FORM,
  authType: "session" as const,
  sessionCookie: "sid=abc123",
  authHeaderName: "Authorization",
  authHeaderValue: "Bearer tok999",
  localStorageJson: '{"access_token":"ls123"}',
  sessionCheckUrl: "https://portal.example/dashboard",
  loggedInIndicator: "My Loans",
};
assert.equal(validateDastAuthForm(sessionForm).valid, true);
const sessionPayload = buildDastAuthPayload(sessionForm);
assert.equal(sessionPayload.auth_type, "session");
assert.equal(sessionPayload.session_cookie, "sid=abc123");
assert.equal(sessionPayload.auth_header_name, "Authorization");
assert.equal(sessionPayload.auth_header_value, "Bearer tok999");
assert.equal(sessionPayload.session_check_url, "https://portal.example/dashboard");

// 3. 2-step OTP form validation + payload (static OTP + MPIN, and TOTP)
const otpForm = {
  ...EMPTY_DAST_AUTH_FORM,
  authType: "otp_form" as const,
  loginUrl: "https://portal.example/login",
  username: "7011554991",
  xpathUsername: "//input[@name='mobile']",
  xpathSendOtp: "//button[@id='send']",
  xpathOtp: "//div[@id='otp-boxes']",
  xpathSubmit: "//button[@id='verify']",
  otpSource: "static" as const,
  otpCode: "123456",
  mpin: "4321",
  xpathMpin: "//input[@name='mpin']",
  xpathMpinSubmit: "//button[@id='confirm']",
};
assert.equal(validateDastAuthForm(otpForm).valid, true);
assert.equal(validateDastAuthForm({ ...otpForm, xpathMpin: "" }).valid, false, "mpin without xpath is invalid");
const otpPayload = buildDastAuthPayload(otpForm);
assert.equal(otpPayload.auth_type, "otp_form");
assert.equal(otpPayload.otp_code, "123456");
assert.equal(otpPayload.mpin, "4321");

// Blank secrets omitted on profile edit
const editPayload = buildDastAuthPayload({ ...otpForm, otpCode: "", mpin: "" }, { omitBlankSecrets: true });
assert.equal(editPayload.otp_code, undefined);
assert.equal(editPayload.mpin, undefined);

// TOTP source validation
const totpForm = { ...otpForm, otpSource: "totp" as const, otpCode: "", totpSecret: "JBSWY3DPEHPK3PXP", mpin: "", xpathMpin: "" };
assert.equal(validateDastAuthForm(totpForm).valid, true);
assert.equal(validateDastAuthForm({ ...totpForm, totpSecret: "" }).valid, false);

// 4. Rerun prefill preserves OTP/session non-secret fields and NEVER copies secrets
const otpRerun = dastRerunPrefill({
  scan_metadata: {
    target_url: "https://portal.example",
    scan_speed: "medium",
    max_urls: 25,
    auth: {
      auth_type: "otp_form",
      login_url: "https://portal.example/login",
      username: "7011554991",
      xpath_of_username_field: "//input[@name='mobile']",
      xpath_of_send_otp_button: "//button[@id='send']",
      xpath_of_otp_field: "//div[@id='otp-boxes']",
      xpath_of_submit_button: "//button[@id='verify']",
      otp_source: "static",
      otp_code: "Canary-OTP-999",
      mpin: "Canary-MPIN-888",
      session_cookie: "Canary-Cookie-777",
    },
  },
});
assert.equal(otpRerun?.auth_type, "otp_form");
assert.equal(otpRerun?.xpath_otp, "//div[@id='otp-boxes']");
assert.ok(!JSON.stringify(otpRerun).includes("Canary-"));

// 5. Public profile hydration leaves secrets empty
const hydrated = authFormFromPublic({
  auth_type: "otp_form",
  login_url: "https://portal.example/login",
  username: "7011554991",
  xpath_of_username_field: "//input[@name='mobile']",
  xpath_of_otp_field: "//input[@name='otp']",
  xpath_of_submit_button: "//button",
  otp_source: "totp",
});
assert.equal(hydrated.authType, "otp_form");
assert.equal(hydrated.otpSource, "totp");
assert.equal(hydrated.totpSecret, "");
assert.equal(hydrated.otpCode, "");

console.log("dast auth form: tests passed");

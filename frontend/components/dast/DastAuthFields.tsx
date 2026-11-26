"use client";

import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { FieldLabel } from "@/components/ui/info-tip";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { DastAuthType, DastOtpSource } from "@/utils/backend_api";
import type { DastAuthFormState } from "@/utils/dastAuthForm";

interface DastAuthFieldsProps {
  value: DastAuthFormState;
  onChange: (next: DastAuthFormState) => void;
  /** "sidebar" matches the dark DAST options sidebar; "card" matches the light/dark Profiles card. */
  variant?: "sidebar" | "card";
  /** True when editing an existing saved profile (blank secrets keep stored encrypted values). */
  isEditing?: boolean;
  /** Prefix for DOM ids so sidebar and profiles never collide. */
  idPrefix?: string;
}

export function DastAuthFields({
  value,
  onChange,
  variant = "sidebar",
  isEditing = false,
  idPrefix = "dast-auth",
}: DastAuthFieldsProps) {
  const isSidebar = variant === "sidebar";
  const labelClass = isSidebar ? "text-zinc-300" : undefined;
  const inputClass = isSidebar
    ? "bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
    : "w-full";
  const triggerClass = isSidebar
    ? "bg-zinc-800 border-zinc-700 text-white w-full cursor-pointer"
    : "w-full cursor-pointer";
  const contentClass = isSidebar ? "bg-zinc-800 border-zinc-700" : undefined;
  const itemClass = isSidebar ? "text-white hover:bg-zinc-700 cursor-pointer" : "cursor-pointer";
  const hintClass = isSidebar ? "text-xs text-zinc-400" : "text-xs text-zinc-500";
  const secretPlaceholder = (fallback: string) => (isEditing ? "Leave blank to keep saved value" : fallback);

  const set = <K extends keyof DastAuthFormState>(key: K, val: DastAuthFormState[K]) => {
    onChange({ ...value, [key]: val });
  };

  return (
    <div className="space-y-3 w-full">
      <div className="space-y-1.5">
        <FieldLabel htmlFor={`${idPrefix}-type`} infoId="dast.cfg.auth_type" labelClassName={labelClass} required>
          Authentication method
        </FieldLabel>
        <Select
          value={value.authType}
          onValueChange={(v) => set("authType", v as DastAuthType)}
        >
          <SelectTrigger id={`${idPrefix}-type`} data-testid="dast-auth-type-select" className={triggerClass}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent className={contentClass}>
            <SelectItem value="password" className={itemClass}>
              Username &amp; Password
            </SelectItem>
            <SelectItem value="session" className={itemClass}>
              Session Import (Live SMS OTP / CAPTCHA)
            </SelectItem>
            <SelectItem value="otp_form" className={itemClass}>
              2-Step Mobile / OTP Login (UAT / TOTP)
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      {value.authType === "password" && (
        <div className="space-y-3" data-testid="dast-auth-password-fields">
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-login-url`} infoId="dast.cfg.login_url" labelClassName={labelClass} required>
              Login URL
            </FieldLabel>
            <Input
              id={`${idPrefix}-login-url`}
              type="url"
              placeholder="https://example.com/login"
              className={inputClass}
              value={value.loginUrl}
              onChange={(e) => set("loginUrl", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-xpath-user`} infoId="dast.cfg.xpath_user" labelClassName={labelClass} required>
              XPath of username field
            </FieldLabel>
            <Input
              id={`${idPrefix}-xpath-user`}
              placeholder="//input[@name='username']"
              className={inputClass}
              value={value.xpathUsername}
              onChange={(e) => set("xpathUsername", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-xpath-pass`} infoId="dast.cfg.xpath_pass" labelClassName={labelClass} required>
              XPath of password field
            </FieldLabel>
            <Input
              id={`${idPrefix}-xpath-pass`}
              placeholder="//input[@name='password']"
              className={inputClass}
              value={value.xpathPassword}
              onChange={(e) => set("xpathPassword", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-username`} infoId="dast.cfg.username" labelClassName={labelClass} required>
              Username
            </FieldLabel>
            <Input
              id={`${idPrefix}-username`}
              placeholder="user@example.com"
              autoComplete="off"
              className={inputClass}
              value={value.username}
              onChange={(e) => set("username", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-password`} infoId="dast.cfg.password" labelClassName={labelClass} required={!isEditing}>
              Password
            </FieldLabel>
            <Input
              id={`${idPrefix}-password`}
              type="password"
              autoComplete="new-password"
              placeholder={secretPlaceholder("••••••••")}
              className={inputClass}
              value={value.password}
              onChange={(e) => set("password", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-xpath-submit`} infoId="dast.cfg.xpath_submit" labelClassName={labelClass} required>
              XPath of submit button
            </FieldLabel>
            <Input
              id={`${idPrefix}-xpath-submit`}
              placeholder="//button[@type='submit']"
              className={inputClass}
              value={value.xpathSubmit}
              onChange={(e) => set("xpathSubmit", e.target.value)}
            />
          </div>
        </div>
      )}

      {value.authType === "session" && (
        <div className="space-y-3" data-testid="dast-auth-session-fields">
          <p className={hintClass}>
            Sign in once in your browser (completing SMS OTP, MPIN, or CAPTCHA), then paste at least one session credential below. The scanner verifies the session before crawling and fails fast with an automatic refund if expired.
          </p>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-session-cookie`} infoId="dast.cfg.session_cookie" labelClassName={labelClass}>
              Session Cookie header
            </FieldLabel>
            <Textarea
              id={`${idPrefix}-session-cookie`}
              rows={2}
              placeholder={secretPlaceholder("sessionid=...; csrftoken=...")}
              className={inputClass}
              value={value.sessionCookie}
              onChange={(e) => set("sessionCookie", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-header-name`} infoId="dast.cfg.auth_header_name" labelClassName={labelClass}>
              Auth header name
            </FieldLabel>
            <Input
              id={`${idPrefix}-header-name`}
              placeholder="Authorization"
              className={inputClass}
              value={value.authHeaderName}
              onChange={(e) => set("authHeaderName", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-header-value`} infoId="dast.cfg.auth_header_value" labelClassName={labelClass}>
              Auth header value
            </FieldLabel>
            <Input
              id={`${idPrefix}-header-value`}
              type="password"
              autoComplete="new-password"
              placeholder={secretPlaceholder("Bearer eyJhbGciOi...")}
              className={inputClass}
              value={value.authHeaderValue}
              onChange={(e) => set("authHeaderValue", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-local-storage`} infoId="dast.cfg.local_storage_json" labelClassName={labelClass}>
              localStorage JSON
            </FieldLabel>
            <Textarea
              id={`${idPrefix}-local-storage`}
              rows={2}
              placeholder={secretPlaceholder('{"access_token": "eyJ..."}')}
              className={inputClass}
              value={value.localStorageJson}
              onChange={(e) => set("localStorageJson", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-session-storage`} infoId="dast.cfg.session_storage_json" labelClassName={labelClass}>
              sessionStorage JSON
            </FieldLabel>
            <Textarea
              id={`${idPrefix}-session-storage`}
              rows={2}
              placeholder={secretPlaceholder('{"auth_state": "active"}')}
              className={inputClass}
              value={value.sessionStorageJson}
              onChange={(e) => set("sessionStorageJson", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-session-check-url`} infoId="dast.cfg.session_check_url" labelClassName={labelClass}>
              Session check URL
            </FieldLabel>
            <Input
              id={`${idPrefix}-session-check-url`}
              type="url"
              placeholder="https://example.com/dashboard"
              className={inputClass}
              value={value.sessionCheckUrl}
              onChange={(e) => set("sessionCheckUrl", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-logged-in-indicator`} infoId="dast.cfg.logged_in_indicator" labelClassName={labelClass}>
              Logged-in text
            </FieldLabel>
            <Input
              id={`${idPrefix}-logged-in-indicator`}
              placeholder="Logout or My Loans"
              className={inputClass}
              value={value.loggedInIndicator}
              onChange={(e) => set("loggedInIndicator", e.target.value)}
            />
          </div>
        </div>
      )}

      {value.authType === "otp_form" && (
        <div className="space-y-3" data-testid="dast-auth-otp-fields">
          <p className={hintClass}>
            Signs in once using a headless browser (mobile/email → Send OTP → OTP → optional MPIN), captures the session, and reuses it across every page without re-triggering OTP.
          </p>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-otp-login-url`} infoId="dast.cfg.login_url" labelClassName={labelClass} required>
              Login URL
            </FieldLabel>
            <Input
              id={`${idPrefix}-otp-login-url`}
              type="url"
              placeholder="https://example.com/login"
              className={inputClass}
              value={value.loginUrl}
              onChange={(e) => set("loginUrl", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-otp-username`} infoId="dast.cfg.username" labelClassName={labelClass} required>
              Mobile number or email
            </FieldLabel>
            <Input
              id={`${idPrefix}-otp-username`}
              placeholder="7011554991"
              autoComplete="off"
              className={inputClass}
              value={value.username}
              onChange={(e) => set("username", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-otp-xpath-user`} infoId="dast.cfg.xpath_user" labelClassName={labelClass} required>
              Mobile / email field XPath
            </FieldLabel>
            <Input
              id={`${idPrefix}-otp-xpath-user`}
              placeholder="//input[@name='mobile']"
              className={inputClass}
              value={value.xpathUsername}
              onChange={(e) => set("xpathUsername", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-xpath-send-otp`} infoId="dast.cfg.xpath_send_otp" labelClassName={labelClass}>
              Send OTP button XPath
            </FieldLabel>
            <Input
              id={`${idPrefix}-xpath-send-otp`}
              placeholder="//button[contains(.,'Send OTP')]"
              className={inputClass}
              value={value.xpathSendOtp}
              onChange={(e) => set("xpathSendOtp", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-xpath-otp`} infoId="dast.cfg.xpath_otp" labelClassName={labelClass} required>
              OTP input XPath
            </FieldLabel>
            <Input
              id={`${idPrefix}-xpath-otp`}
              placeholder="//input[@name='otp'] or //div[@id='otp-boxes']"
              className={inputClass}
              value={value.xpathOtp}
              onChange={(e) => set("xpathOtp", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-otp-source`} infoId="dast.cfg.otp_source" labelClassName={labelClass} required>
              OTP source
            </FieldLabel>
            <Select
              value={value.otpSource}
              onValueChange={(v) => set("otpSource", v as DastOtpSource)}
            >
              <SelectTrigger id={`${idPrefix}-otp-source`} data-testid="dast-otp-source-select" className={triggerClass}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent className={contentClass}>
                <SelectItem value="static" className={itemClass}>
                  Static test OTP (UAT / Staging)
                </SelectItem>
                <SelectItem value="totp" className={itemClass}>
                  TOTP authenticator secret (RFC 6238)
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          {value.otpSource === "static" ? (
            <div className="space-y-1.5">
              <FieldLabel htmlFor={`${idPrefix}-otp-code`} infoId="dast.cfg.otp_code" labelClassName={labelClass} required={!isEditing}>
                Static OTP code
              </FieldLabel>
              <Input
                id={`${idPrefix}-otp-code`}
                type="password"
                autoComplete="one-time-code"
                placeholder={secretPlaceholder("123456")}
                className={inputClass}
                value={value.otpCode}
                onChange={(e) => set("otpCode", e.target.value)}
              />
            </div>
          ) : (
            <div className="space-y-1.5">
              <FieldLabel htmlFor={`${idPrefix}-totp-secret`} infoId="dast.cfg.totp_secret" labelClassName={labelClass} required={!isEditing}>
                TOTP secret (Base32)
              </FieldLabel>
              <Input
                id={`${idPrefix}-totp-secret`}
                type="password"
                autoComplete="new-password"
                placeholder={secretPlaceholder("JBSWY3DPEHPK3PXP")}
                className={inputClass}
                value={value.totpSecret}
                onChange={(e) => set("totpSecret", e.target.value)}
              />
            </div>
          )}
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-otp-xpath-submit`} infoId="dast.cfg.xpath_submit" labelClassName={labelClass} required>
              Verify / Submit button XPath
            </FieldLabel>
            <Input
              id={`${idPrefix}-otp-xpath-submit`}
              placeholder="//button[contains(.,'Verify')]"
              className={inputClass}
              value={value.xpathSubmit}
              onChange={(e) => set("xpathSubmit", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-mpin`} infoId="dast.cfg.mpin" labelClassName={labelClass}>
              MPIN (optional)
            </FieldLabel>
            <Input
              id={`${idPrefix}-mpin`}
              type="password"
              autoComplete="new-password"
              placeholder={secretPlaceholder("Leave blank if no MPIN step")}
              className={inputClass}
              value={value.mpin}
              onChange={(e) => set("mpin", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-xpath-mpin`} infoId="dast.cfg.xpath_mpin" labelClassName={labelClass}>
              MPIN field XPath
            </FieldLabel>
            <Input
              id={`${idPrefix}-xpath-mpin`}
              placeholder="//input[@name='mpin']"
              className={inputClass}
              value={value.xpathMpin}
              onChange={(e) => set("xpathMpin", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-xpath-mpin-submit`} infoId="dast.cfg.xpath_mpin_submit" labelClassName={labelClass}>
              MPIN submit button XPath
            </FieldLabel>
            <Input
              id={`${idPrefix}-xpath-mpin-submit`}
              placeholder="//button[contains(.,'Confirm')]"
              className={inputClass}
              value={value.xpathMpinSubmit}
              onChange={(e) => set("xpathMpinSubmit", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-otp-check-url`} infoId="dast.cfg.session_check_url" labelClassName={labelClass}>
              Session check URL
            </FieldLabel>
            <Input
              id={`${idPrefix}-otp-check-url`}
              type="url"
              placeholder="https://example.com/dashboard"
              className={inputClass}
              value={value.sessionCheckUrl}
              onChange={(e) => set("sessionCheckUrl", e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <FieldLabel htmlFor={`${idPrefix}-otp-indicator`} infoId="dast.cfg.logged_in_indicator" labelClassName={labelClass}>
              Logged-in text
            </FieldLabel>
            <Input
              id={`${idPrefix}-otp-indicator`}
              placeholder="Logout or My Loans"
              className={inputClass}
              value={value.loggedInIndicator}
              onChange={(e) => set("loggedInIndicator", e.target.value)}
            />
          </div>
        </div>
      )}
    </div>
  );
}
